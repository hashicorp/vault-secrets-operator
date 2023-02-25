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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
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

type VaultClientCacheConfig struct {
	// Persist the Client to K8s Secrets for later cache recovery.
	Persist bool
	// RequireEncryption for persisting Clients i.e. the controller must have VaultTransitRef
	// configured before it will persist the Client to storage. This option requires Persist to be true.
	RequireEncryption bool
	// MaxConcurrentReconciles
	MaxConcurrentReconciles int
}

// VaultClientCacheReconciler reconciles a VaultClientCache object
type VaultClientCacheReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	Config        *VaultClientCacheConfig
	ClientFactory vault.CacheingClientFactory
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

	vClient, ok := r.ClientFactory.Cache().Get(cacheKey)
	if !ok {
		// client recovery from storage is handled by the vault.ClientFactory,
		// as is the creation of VaultClientCache resources.
		var restored bool
		if r.Config.Persist && o.Status.CacheSecretRef != "" {
			if _, err := r.ClientFactory.Restore(ctx, r.Client, o); err == nil {
				o.Status.CacheMisses = 0
				restored = true
			}
		}

		if !restored {
			o.Status.CacheMisses++
		}

		if o.Status.CacheMisses >= o.Spec.MaxCacheMisses {
			// evict ourselves
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonMaxCacheMisses,
				"Self eviction cacheMisses=%d, maxCacheMisses=%d, cacheKey=%s",
				o.Status.CacheMisses, o.Spec.MaxCacheMisses, cacheKey)
			return r.evictSelf(ctx, o)
		}

		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}

		horizon, _ := computeHorizonWithJitter(time.Duration(o.Spec.CacheFetchInterval))
		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	if err := vClient.Renew(ctx); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonClientTokenRenewal,
			"Failed renewing client token: %s", err)
		return r.evictSelf(ctx, o)
	}

	if r.Config.Persist {
		s, err := r.persistClient(ctx, o, vClient)
		if err != nil {
			if errors.Is(err, vault.EncryptionRequiredError) {
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonPersistenceForbidden,
					"A VaultTransitRef must be configured, encryption is required")
				jitter, _ := computeHorizonWithJitter(time.Duration(o.Spec.CacheFetchInterval))
				return ctrl.Result{
					RequeueAfter: jitter,
				}, nil
			}

			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
				"Failed to persist client to secrets cache")
			return ctrl.Result{}, err
		}
		o.Status.CacheSecretRef = s.Name
	} else {
		o.Status.CacheSecretRef = ""
	}

	if err := r.pruneStorage(ctx, o); err != nil {
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

	horizon, _ := computeHorizonWithJitter(ttl)
	r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonClientTokenRenewal,
		"Renewed client token, horizon=%s", horizon)
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
		r.ClientFactory.Cache().Remove(o.Spec.CacheKey)
		r.Config.Persist = false
		if err := r.pruneStorage(ctx, o); err != nil {
			return ctrl.Result{}, err
		}

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

func (r *VaultClientCacheReconciler) pruneStorage(ctx context.Context, o *secretsv1alpha1.VaultClientCache) error {
	req := vault.ClientCacheStoragePruneRequest{
		MatchingLabels: client.MatchingLabels{
			"cacheKey": o.Spec.CacheKey,
		},
		Filter: func(s corev1.Secret) bool {
			if !r.Config.Persist {
				// prune all referent Secrets, this is here to handle the case where
				// persistence was previously enabled.
				return false
			}
			return s.Name == o.Status.CacheSecretRef
		},
	}

	count, err := r.ClientFactory.Storage().Prune(ctx, r.Client, req)
	if r.Config.Persist && count > 1 || !r.Config.Persist && count > 0 {
		r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonPersistentCacheCleanup,
			"Purged %d referent Secret resources", count)
	}

	return err
}

func (r *VaultClientCacheReconciler) persistClient(ctx context.Context, o *secretsv1alpha1.VaultClientCache, vClient vault.Client) (*corev1.Secret, error) {
	requireEncryption := r.Config.RequireEncryption
	transitObjKey := client.ObjectKey{}

	if o.Spec.VaultTransitRef != "" {
		transitObjKey.Namespace = o.Namespace
		transitObjKey.Name = o.Spec.VaultTransitRef
		requireEncryption = true
	}

	req := vault.ClientCacheStorageRequest{
		Requestor:         client.ObjectKeyFromObject(o),
		TransitObjKey:     transitObjKey,
		Client:            vClient,
		RequireEncryption: requireEncryption,
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: o.APIVersion,
				Kind:       o.Kind,
				Name:       o.Name,
				UID:        o.UID,
			},
		},
	}

	return r.ClientFactory.Storage().Store(ctx, r.Client, req)
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
	ctrlOptions := controller.Options{
		// This configurable affects the timeliness when recovering
		// from the storage cache.
		MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultClientCache{}).
		WithOptions(ctrlOptions).
		WithEventFilter(ignoreUpdatePredicate()).
		WithEventFilter(filterNamespacePredicate([]string{common.OperatorNamespace})).
		Complete(r)
}
