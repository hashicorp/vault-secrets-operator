// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

const vaultAuthFinalizer = "vaultauth.secrets.hashicorp.com/finalizer"

// VaultAuthReconciler reconciles a VaultAuth object
type VaultAuthReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	Recorder       record.EventRecorder
	ClientFactory  vault.CachingClientFactory
	referenceCache ResourceReferenceCache
	// GlobalVaultAuthOptions is a struct that contains global VaultAuth options.
	GlobalVaultAuthOptions *common.GlobalVaultAuthOptions
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=get;list;create;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// needed for managing cached Clients, duplicated in vaultconnection_controller.go
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch;deletecollection
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile reconciles the secretsv1beta1.VaultAuth resource.
// Each reconciliation will validate the resource's configuration
//
// Upon deletion of the resource, it will prune all referent Vault Client(s).
func (r *VaultAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	o, err := common.GetVaultAuth(ctx, r.Client, req.NamespacedName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultAuth resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		r.referenceCache.Remove(VaultAuthGlobal, req.NamespacedName)
		metrics.DeleteResourceStatus("vaultauth", o)
		return r.handleFinalizer(ctx, o)
	}

	// assume that status is always invalid
	o.Status.Valid = ptr.To(false)
	var errs error

	var conditions []metav1.Condition
	if o.Spec.VaultAuthGlobalRef != nil {
		condition := metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: o.Generation,
			Reason:             "VaultAuthGlobalRef",
		}

		mObj, gObj, err := common.MergeInVaultAuthGlobal(ctx, r.Client, o, r.GlobalVaultAuthOptions)
		if err != nil {
			errs = errors.Join(errs, err)
			condition.Message = err.Error()
			condition.Status = metav1.ConditionFalse
		} else {
			o = mObj
			condition.Message = fmt.Sprintf(
				"VaultAuthGlobal successfully merged, key=%s, uid=%s, generation=%d",
				client.ObjectKeyFromObject(gObj), gObj.UID, gObj.Generation)
			r.referenceCache.Set(
				VaultAuthGlobal, req.NamespacedName,
				client.ObjectKeyFromObject(gObj))
		}
		conditions = append(conditions, condition)
	} else {
		r.referenceCache.Remove(VaultAuthGlobal, req.NamespacedName)
	}

	// ensure that the vaultConnectionRef is set for any VaultAuth resource in the operator namespace.
	if o.Namespace == common.OperatorNamespace && o.Spec.VaultConnectionRef == "" {
		err = fmt.Errorf("vaultConnectionRef must be set on resources in the %q namespace", common.OperatorNamespace)
		logger.Error(err, "Invalid resource")
		errs = errors.Join(errs, err)
	}

	connName, err := common.GetConnectionNamespacedName(o)
	if err != nil {
		msg := "Invalid VaultConnectionRef"
		logger.Error(err, msg)
		r.recordEvent(o, consts.ReasonInvalidResourceRef, msg+": %s", err)
		errs = errors.Join(errs, err)
	}

	if _, err = common.GetVaultConnectionWithRetry(ctx, r.Client, connName, time.Millisecond*500, 60); err != nil {
		errs = errors.Join(errs, err)
		logger.Error(err, "Failed to find VaultConnectionRef")
	}

	// hash the VaultAuth.Spec so it can be used to determine if the VaultAuth
	// resource has changed since the last reconciliation.
	b, err := json.Marshal(o.Spec)
	var specHash string
	if err == nil {
		specHash = fmt.Sprintf("%x", blake2b.Sum256(b))
	} else {
		errs = errors.Join(errs, err)
	}

	if errs == nil {
		var pruneAll bool
		if specHash != "" && o.Status.SpecHash != "" {
			pruneAll = specHash != o.Status.SpecHash
		}

		// prune old referent Client from the ClientFactory's cache for all older generations of self.
		// this is a bit of a sledgehammer, not all updated attributes of VaultAuth
		// warrant eviction of a client cache entry, but this is a good start.
		//
		// This is also done in controllers.VaultConnectionReconciler
		logger.V(consts.LogLevelDebug).Info("Prune",
			"pruneAll", pruneAll, "specHash", specHash, "lastSpecHash", o.Status.SpecHash,
			"objectMeta", o.ObjectMeta)
		if _, err := r.ClientFactory.Prune(ctx, r.Client, o, vault.CachingClientFactoryPruneRequest{
			FilterFunc: func(cur, other client.Object) bool {
				if pruneAll {
					// prune all cache refs to this resource from the ClientFactory's cache.
					return filterAllCacheRefs(cur, other)
				}
				// prune all but the current generation of this resource from the ClientFactory's
				// cache.
				return filterOldCacheRefs(cur, other)
			},
			PruneStorage: true,
		}); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	o.Status.SpecHash = specHash

	var horizon time.Duration
	if errs != nil {
		o.Status.Valid = ptr.To(false)
		o.Status.Error = errs.Error()
		horizon = computeHorizonWithJitter(requeueDurationOnError)
	} else {
		o.Status.Valid = ptr.To(true)
		o.Status.Error = ""
	}

	if err := r.updateStatus(ctx, o, conditions...); err != nil {
		return ctrl.Result{}, err
	}

	if errs == nil {
		r.recordEvent(o, consts.ReasonAccepted, "Successfully handled VaultAuth resource request")
	} else {
		logger.Error(errs, "Failed to handle VaultAuth resource request", "horizon", horizon)
		r.recordEvent(o, consts.ReasonAccepted,
			fmt.Sprintf("Failed to handle VaultAuth resource request: err=%s", errs))
	}

	return ctrl.Result{
		RequeueAfter: horizon,
	}, nil
}

func (r *VaultAuthReconciler) recordEvent(o *secretsv1beta1.VaultAuth, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !ptr.Deref(o.Status.Valid, false) {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(o, eventType, reason, msg, i...)
}

func (r *VaultAuthReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultAuth, conditions ...metav1.Condition) error {
	logger := log.FromContext(ctx)
	valid := ptr.Deref(o.Status.Valid, false)
	metrics.SetResourceStatus("vaultauth", o, valid)
	o.Status.Conditions = updateConditions(o.Status.Conditions, append(conditions, newHealthyCondition(o, valid, "VaultAuth"))...)
	if err := r.Status().Update(ctx, o); err != nil {
		logger.Error(err, "Failed to update the resource's status")
		return err
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultAuthFinalizer)
	return err
}

func (r *VaultAuthReconciler) handleFinalizer(ctx context.Context, o *secretsv1beta1.VaultAuth) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultAuthFinalizer) {
		if _, err := r.ClientFactory.Prune(ctx, r.Client, o, vault.CachingClientFactoryPruneRequest{
			FilterFunc:          filterAllCacheRefs,
			PruneStorage:        true,
			SkipClientCallbacks: true,
		}); err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(o, vaultAuthFinalizer)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.referenceCache = NewResourceReferenceCache()
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultAuth{}).
		Watches(
			&secretsv1beta1.VaultAuthGlobal{},
			NewEnqueueRefRequestsHandler(VaultAuthGlobal, r.referenceCache, nil, nil),
		).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
