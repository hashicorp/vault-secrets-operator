// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"

	"github.com/hashicorp/vault-secrets-operator/internal/metrics"

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
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultConnectionFinalizer = "vaultconnection.secrets.hashicorp.com/finalizer"

// VaultConnectionReconciler reconciles a VaultConnection object
type VaultConnectionReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.CachingClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get
// needed for managing cached Clients, duplicated in vaultauth_controller.go
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch;deletecollection

// Reconcile reconciles the secretsv1beta1.VaultConnection resource.
// Upon a reconciliation it will verify that the configured Vault connection is valid.
//
// Upon deletion of the resource, it will prune all referent Vault Client(s).
func (r *VaultConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.VaultConnection{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to retrieve resource from k8s", "connection", o)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		return r.handleFinalizer(ctx, o)
	}

	// assume that status is always invalid
	o.Status.Valid = false

	vaultConfig := &vault.ClientConfig{
		CACertSecretRef: o.Spec.CACertSecretRef,
		K8sNamespace:    o.ObjectMeta.Namespace,
		Address:         o.Spec.Address,
		SkipTLSVerify:   o.Spec.SkipTLSVerify,
		TLSServerName:   o.Spec.TLSServerName,
		Headers:         o.Spec.Headers,
	}

	var errs error
	vaultClient, err := vault.MakeVaultClient(ctx, vaultConfig, r.Client)
	if err != nil {
		logger.Error(err, "Failed to construct Vault client")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError, "Failed to construct Vault client: %s", err)

		errs = errors.Join(errs, err)
	}

	if vaultClient != nil {
		if _, err := vaultClient.Sys().SealStatusWithContext(ctx); err != nil {
			logger.Error(err, "Failed to check Vault seal status, requeuing")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, "VaultClientError", "Failed to check Vault seal status: %s", err)
			errs = errors.Join(errs, err)
		} else {
			o.Status.Valid = true
		}
	}

	// prune old referent Client from the ClientFactory's cache for all older generations of self.
	// this is a bit of a sledgehammer, not all updated attributes of VaultConnection
	// warrant eviction of a client cache entry, but this is a good start.
	//
	// Note: this is also done in controllers.VaultAuthReconciler
	// TODO: consider adding a Predicate to the EventFilter, to filter events that do not result in a change to the Spec.
	if _, err := r.ClientFactory.Prune(ctx, r.Client, o, vault.CachingClientFactoryPruneRequest{
		FilterFunc:   filterOldCacheRefs,
		PruneStorage: true,
	}); err != nil {
		logger.Error(err, "Failed prune Client cache of older generations")
		errs = errors.Join(errs, err)
	}

	if err := r.updateStatus(ctx, o); err != nil {
		errs = errors.Join(errs, err)
	}

	if errs != nil {
		return ctrl.Result{}, errs
	}

	r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonAccepted, "VaultConnection accepted")
	return ctrl.Result{}, nil
}

func (r *VaultConnectionReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultConnection) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("vaultconnection", o, o.Status.Valid)
	if err := r.Status().Update(ctx, o); err != nil {
		logger.Error(err, "Failed to update the resource's status")
		return err
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultConnectionFinalizer)
	return err
}

func (r *VaultConnectionReconciler) handleFinalizer(ctx context.Context, o *secretsv1beta1.VaultConnection) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultConnectionFinalizer) {
		if _, err := r.ClientFactory.Prune(ctx, r.Client, o, vault.CachingClientFactoryPruneRequest{
			FilterFunc:          filterAllCacheRefs,
			PruneStorage:        true,
			SkipClientCallbacks: true,
		}); err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(o, vaultConnectionFinalizer)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultConnection{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
