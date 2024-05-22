// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultAuthFinalizer = "vaultauth.secrets.hashicorp.com/finalizer"

// VaultAuthReconciler reconciles a VaultAuth object
type VaultAuthReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.CachingClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=get;list;create;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// needed for managing cached Clients, duplicated in vaultconnection_controller.go
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch;deletecollection
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

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
		return r.handleFinalizer(ctx, o)
	}

	// assume that status is always invalid
	o.Status.Valid = false

	var errs error
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

	// prune old referent Client from the ClientFactory's cache for all older generations of self.
	// this is a bit of a sledgehammer, not all updated attributes of VaultConnection
	// warrant eviction of a client cache entry, but this is a good start.
	//
	// This is also done in controllers.VaultConnectionReconciler
	// TODO: consider adding a Predicate to the EventFilter, to filter events that do not result in a change to the Spec.
	if _, err := r.ClientFactory.Prune(ctx, r.Client, o, vault.CachingClientFactoryPruneRequest{
		FilterFunc:   filterOldCacheRefs,
		PruneStorage: true,
	}); err != nil {
		errs = errors.Join(errs, err)
	}

	if errs == nil {
		o.Status.Valid = true
	} else {
		o.Status.Error = errs.Error()
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	r.recordEvent(o, consts.ReasonAccepted, "Successfully handled VaultAuth resource request")
	return ctrl.Result{}, nil
}

func (r *VaultAuthReconciler) recordEvent(a *secretsv1beta1.VaultAuth, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !a.Status.Valid {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(a, eventType, reason, msg, i...)
}

func (r *VaultAuthReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultAuth) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("vaultauth", o, o.Status.Valid)
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultAuth{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
