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
}

// VaultClientCacheReconciler reconciles a VaultClientCache object
type VaultClientCacheReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	Config        VaultClientCacheConfig
	ClientFactory vault.CachingClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultclientcaches/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch

// Reconcile ensures that the vault.Client is periodically renewed within valid renewal window.
// The renewal window is always calculated from the Vault client token's TTL.
//
// If a vault.Client renewal fails for any reason the in-memory vault.ClientCache will be cleared
// of the invalid vault.Client, and the CustomResource being reconciled will be deleted.
//
// If the renewal succeeds, then another reconcile will be queued for the vault.Client.
// The reconciliation is always scheduled to occur before the vault.Client token has expired.
//
// In the case where VaultClientCacheConfig.Persist is enabled, the successfully renewed vault.Client
// will be stored in the vault.ClientCacheStorage.
//
// In VaultClientCacheConfig.Persist is enabled and the vault.Client is not found in the vault.ClientCache,
// an attempt will be made to restore the vault.Client from the vault.ClientCacheStorage. If the attempt
// fails the CustomResource being reconciled will be deleted.
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

	logger.Info("Handling request", "config", r.Config)

	if o.GetDeletionTimestamp() == nil {
		if err := r.addFinalizer(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Got deletion timestamp", "obj", o)
		// status update will be taken care of in the call to handleFinalizer()
		return r.handleFinalizer(ctx, o)
	}

	cacheKey, err := r.genCacheKey(o)
	if err != nil {
		return r.evictSelf(ctx, o)
	}

	var restored bool
	vClient, ok := r.ClientFactory.Cache().Get(cacheKey)
	if !ok {
		// client recovery from storage is handled by the vault.ClientFactory,
		// as is the creation of VaultClientCache resources.
		// var restored bool
		if r.Config.Persist {
			vClient, err = r.ClientFactory.Restore(ctx, r.Client, o)
			if err != nil {
				// prune all with cacheKey, in the case where a restoration request failed.
				if err := r.pruneStorage(ctx, o, true); err != nil {
					r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonMaxCacheMisses,
						"Failed to prune storage, err=%s", err)
				}
			} else {
				restored = true
			}
		}
	}

	if vClient == nil {
		o.Status.CacheMisses++
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

		horizon, _ := computeHorizonWithJitter(time.Second * time.Duration(o.Spec.CacheFetchInterval))
		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	if !restored {
		if err := vClient.Renew(ctx); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonClientTokenRenewal,
				"Failed renewing client token: %s", err)
			return r.evictSelf(ctx, o)
		}
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
	if !r.Config.Persist {
		// ensure that CacheSecretRef is empty in the case where we are not configured for persistence.
		logger.Info("Persistence not configured")
		o.Status.CacheSecretRef = ""
	} else {
		logger.Info("Configured for persistence")
		s, err := r.persistClient(ctx, o, vClient)
		if err != nil {
			logger.Error(err, "Failed to persist the client")
			if errors.Is(err, vault.EncryptionRequiredError) {
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonPersistenceForbidden,
					"A VaultTransitRef must be configured, encryption is required")
				horizon, _ := computeHorizonWithJitter(time.Duration(o.Spec.CacheFetchInterval))
				// invalidate the persistent cache for this cacheKey when the storage entry is not encrypted.
				if err := r.pruneStorage(ctx, o, true); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{
					RequeueAfter: horizon,
				}, nil
			}

			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
				"Failed to persist client to secrets cache")
			return ctrl.Result{}, err
		}
		logger.Info("Persisted secret", "name", s.Name)
		o.Status.CacheSecretRef = s.Name
	}

	o.Status.CacheMisses = 0
	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.pruneStorage(ctx, o, false); err != nil {
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
		cacheKey, err := r.genCacheKey(o)
		if err != nil {
			// this should never happen.
		}
		if cacheKey != "" {
			r.ClientFactory.Cache().Remove(cacheKey)
		}

		if err := r.pruneStorage(ctx, o, true); err != nil {
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

func (r *VaultClientCacheReconciler) genCacheKey(o *secretsv1alpha1.VaultClientCache) (string, error) {
	cacheKey, err := vault.GenCacheKeyFromObjName(o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonInvalidCacheKey,
			"Failed to get cacheKey from name, err=%s", err)
		return "", err
	}

	return cacheKey, nil
}

func (r *VaultClientCacheReconciler) pruneStorage(ctx context.Context, o *secretsv1alpha1.VaultClientCache, all bool) error {
	cacheKey, err := r.genCacheKey(o)
	if err != nil {
		return err
	}

	req := vault.ClientCacheStoragePruneRequest{
		MatchingLabels: client.MatchingLabels{
			"cacheKey": cacheKey,
		},
		Filter: func(s corev1.Secret) bool {
			if !r.Config.Persist || all {
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
	enforceEncryption := r.ClientFactory.Storage().EnforceEncryption()
	transitObjKey := client.ObjectKey{}

	if o.Spec.VaultTransitRef != "" {
		transitObjKey.Namespace = o.Namespace
		transitObjKey.Name = o.Spec.VaultTransitRef
		enforceEncryption = true
	}

	req := vault.ClientCacheStorageRequest{
		Requestor:         client.ObjectKeyFromObject(o),
		TransitObjKey:     transitObjKey,
		Client:            vClient,
		EnforceEncryption: enforceEncryption,
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
		logger.Error(err, "Failed to update the resource's status")
		return err

	}

	logger.Info("Updated status", "status", o.Status)
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultClientCacheReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultClientCache{}).
		WithOptions(opts).
		WithEventFilter(ignoreUpdatePredicate()).
		WithEventFilter(filterNamespacePredicate([]string{common.OperatorNamespace})).
		Complete(r)
}
