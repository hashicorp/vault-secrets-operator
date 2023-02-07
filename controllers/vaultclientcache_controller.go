// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const (
	vaultClientCacheFinalizer = "vaultclientcache.secrets.hashicorp.com/finalizer"
)

type VaultClientCacheOptions struct {
	// Persist the Client to K8s Secrets for later cache recovery.
	Persist bool
	// RequireEncryption for persisting Clients i.e. the controller must have VaultTransitRef
	// configured before it will persist the Client to storage. This option requires Persist to be true.
	RequireEncryption bool
}

// VaultClientCacheReconciler reconciles a VaultClientCache object
type VaultClientCacheReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Recorder     record.EventRecorder
	PersistCache bool
	Options      *VaultClientCacheOptions
	ClientCache  vault.ClientCache
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the VaultClientCache object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *VaultClientCacheReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	o := &secretsv1alpha1.VaultClientCache{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "obj", o)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() == nil {
		if err := r.addFinalizer(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Got deletion timestamp", "obj", o)
		// status update will be taken care of in the call to handleFinalizer()
		return r.handleFinalizer(ctx, o)
	}

	cacheKey, err := vault.GenCacheClientKeyFromClientCacheObj(o)
	if err != nil {
		return r.evictSelf(ctx, o)
	}

	if cacheKey != o.Spec.CacheKey {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonInvalidCacheKey,
			"Computed cacheKey %q does not match expected %q", cacheKey, o.Spec.CacheKey)

		return r.evictSelf(ctx, o)
	}

	vClient, ok := r.ClientCache.Get(cacheKey)
	if !ok {
		o.Status.CacheMisses++
		if o.Status.CacheMisses > o.Spec.MaxCacheMisses {
			// evict ourselves
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonMaxCacheMisses,
				"Self eviction cacheMisses=%d, maxCacheMisses=%d, cacheKey=%s",
				o.Status.CacheMisses, o.Spec.MaxCacheMisses, cacheKey)
			return r.evictSelf(ctx, o)
		}
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(time.Duration(o.Spec.CacheFetchInterval)),
		}, nil
	}

	if err := vClient.Renew(ctx); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonClientTokenRenewal,
			"Failed renewing client token: %s", err)
		return r.evictSelf(ctx, o)
	}
	r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonClientTokenRenewal,
		"Successfully renewed the client token")

	if r.Options.Persist {
		if r.Options.RequireEncryption && o.Spec.VaultTransitRef == "" {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonPersistenceForbidden,
				"A VaultTransitRef must be configured, encryption is required")
			return ctrl.Result{
				RequeueAfter: computeHorizonWithJitter(time.Duration(o.Spec.CacheFetchInterval)),
			}, nil
		}

		s, err := r.persistClient(ctx, o, vClient)
		if err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError, "Failed to persist client to secrets cache")
			return ctrl.Result{}, err
		}
		o.Status.CacheSecretRef = s.Name
	}

	if err := r.purgeOrphanSecrets(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	ttl, _ := vClient.GetTokenTTL()
	if ttl <= 0 {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonInvalidTokenTTL,
			"Token TTL is %s", ttl)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientCacheEviction,
			"Invalid token TTL")
		return r.evictSelf(ctx, o)
	}

	o.Status.CacheMisses = 0

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	horizon := computeHorizonWithJitter(ttl)
	logger.Info("Requeue", "horizon", horizon)
	return ctrl.Result{RequeueAfter: horizon}, nil
}

func (r *VaultClientCacheReconciler) evictSelf(ctx context.Context, o *secretsv1alpha1.VaultClientCache) (ctrl.Result, error) {
	if err := r.Client.Delete(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError, "Self eviction failed: %s", err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *VaultClientCacheReconciler) handleFinalizer(ctx context.Context, o *secretsv1alpha1.VaultClientCache) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultClientCacheFinalizer) {
		controllerutil.RemoveFinalizer(o, vaultClientCacheFinalizer)
		r.ClientCache.Remove(o.Spec.CacheKey)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *VaultClientCacheReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultClientCache) error {
	if !controllerutil.ContainsFinalizer(o, vaultClientCacheFinalizer) {
		controllerutil.AddFinalizer(o, vaultClientCacheFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}

	return nil
}

func (r *VaultClientCacheReconciler) purgeOrphanSecrets(ctx context.Context, o *secretsv1alpha1.VaultClientCache) error {
	secrets := &corev1.SecretList{}
	labels := client.MatchingLabels{
		"cacheKey": o.Spec.CacheKey,
	}
	if err := r.Client.List(ctx, secrets, labels); err != nil {
		return err
	}
	var purged []string
	var err error
	for _, item := range secrets.Items {
		if item.Name == o.Status.CacheSecretRef {
			continue
		}
		dcObj := item.DeepCopy()
		if err = r.Client.Delete(ctx, dcObj); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			// requires go1.20+
			err = errors.Join(err)
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
				"Failed to delete %s, on change to %s", item, o)
			continue
		}
		purged = append(purged, client.ObjectKeyFromObject(dcObj).String())
	}

	// it's normal to purge the last created secret, so we can conditionally
	// record an event for a larger batch of secrets.
	if len(purged) > 1 {
		r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonPersistentCacheCleanup,
			"Purged %d of %d referent Secret resources: %v", len(purged), len(secrets.Items), purged)
	}

	return err
}

func (r *VaultClientCacheReconciler) persistClient(ctx context.Context, o *secretsv1alpha1.VaultClientCache, vClient vault.Client) (*corev1.Secret, error) {
	sec, err := vClient.GetLastResponse()
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(sec)
	if err != nil {
		// should never happen
		r.Recorder.Eventf(o, corev1.EventTypeWarning,
			"busted", "JSON marshal failure: %s", err)
		return nil, err
	}

	secretLabels := map[string]string{
		"cacheKey": o.Spec.CacheKey,
	}
	if o.Spec.VaultTransitRef != "" {
		// needed for restore
		secretLabels["encrypted"] = "true"
		secretLabels["vaultTransitRef"] = o.Spec.VaultTransitRef

		transitObjKey := client.ObjectKey{
			Namespace: o.Namespace,
			Name:      o.Spec.VaultTransitRef,
		}
		if encBytes, err := vault.EncryptWithTransitFromObjKey(ctx, r.Client, transitObjKey, b); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning,
				consts.ReasonTransitEncryptError, "Failed to encrypt client using Transit %s: %s", transitObjKey, err)
			return nil, err
		} else {
			b = encBytes
			r.Recorder.Eventf(o, corev1.EventTypeNormal,
				consts.ReasonTransitEncryptSuccessful, "Encrypted client using Transit %s", transitObjKey)
		}
	}

	s := &corev1.Secret{
		Immutable: pointer.Bool(true),
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: o.Name + "-",
			Namespace:    o.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: o.APIVersion,
					Kind:       o.Kind,
					Name:       o.Name,
					UID:        o.UID,
				},
			},
			Labels: secretLabels,
		},
		Data: map[string][]byte{
			"secret": b,
		},
	}

	if err := r.Client.Create(ctx, s); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError, "could not create k8s secret: %s", err)
		return nil, err
	}
	return s, nil
}

func (r *VaultClientCacheReconciler) updateStatus(ctx context.Context, o *secretsv1alpha1.VaultClientCache) error {
	logger := log.FromContext(ctx)
	if err := r.Status().Update(ctx, o); err != nil {
		msg := "Failed to update the resource's status, err=%s"
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError, msg, err)
		logger.Error(err, msg)
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultClientCacheReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultClientCache{}).
		WithEventFilter(ignoreUpdatePredicate()).
		WithEventFilter(filterNamespacePredicate([]string{common.OperatorNamespace})).
		Complete(r)
}
