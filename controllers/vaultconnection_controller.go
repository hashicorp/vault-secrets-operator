// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	client2 "github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultConnectionFinalizer = "vaultconnection.secrets.hashicorp.com/finalizer"

// VaultConnectionReconciler reconciles a VaultConnection object
type VaultConnectionReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultconnections/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultConnection object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *VaultConnectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	logger := log.FromContext(ctx)

	o := &secretsv1alpha1.VaultConnection{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to retrieve resource from k8s", "connection", o)
		return ctrl.Result{}, err
	}

	logger.Info("Handling request", "req", req, "object", o, "deletionTS", o.DeletionTimestamp)
	if o.GetDeletionTimestamp() == nil {
		if err := r.addFinalizer(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Got deletion timestamp", "obj", o)
		return r.handleFinalizer(ctx, o)
	}

	defer func() {
		if updateErr := r.Client.Status().Update(ctx, o); updateErr != nil {
			logger.Error(updateErr, "Failed to update VaultConnection status", "new status", o.Status)
			// add the update error to the returned err from Reconcile
			err = errors.Join(err, updateErr)
		}
	}()

	vaultConfig := &client2.ClientConfig{
		CACertSecretRef: o.Spec.CACertSecretRef,
		K8sNamespace:    o.ObjectMeta.Namespace,
		Address:         o.Spec.Address,
		SkipTLSVerify:   o.Spec.SkipTLSVerify,
		TLSServerName:   o.Spec.TLSServerName,
	}
	vaultClient, err := client2.MakeVaultClient(ctx, vaultConfig, r.Client)
	if err != nil {
		o.Status.Valid = false
		logger.Error(err, "Failed to construct Vault client")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError, "Failed to construct Vault client: %s", err)
		return ctrl.Result{}, err
	}

	if _, err := vaultClient.Sys().SealStatusWithContext(ctx); err != nil {
		o.Status.Valid = false
		logger.Error(err, "Failed to check Vault seal status, requeuing")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, "VaultClientError", "Failed to check Vault seal status: %s", err)
		return ctrl.Result{}, err
	}

	o.Status.Valid = true

	// evict old referent VaultClientCaches for all older generations of self.
	// this is a bit of a sledgehammer, not all updated attributes of VaultConnection
	// warrant eviction of a client cache entry, but this is a good start.
	opts := cacheEvictionOption{
		filterFunc: filterOldCacheRefsForConn,
		matchingLabels: client.MatchingLabels{
			"vaultConnectionRef":          o.GetName(),
			"vaultConnectionRefNamespace": o.GetNamespace(),
		},
	}
	if _, err := evictClientCacheRefs(ctx, r.Client, o, r.Recorder, opts); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
			"Failed to evict referent VaultCacheClient resources: %s", err)
	}

	r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonAccepted, "VaultConnection accepted")
	return ctrl.Result{}, nil
}

func (r *VaultConnectionReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultConnection) error {
	if !controllerutil.ContainsFinalizer(o, vaultConnectionFinalizer) {
		controllerutil.AddFinalizer(o, vaultConnectionFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}

	return nil
}

func (r *VaultConnectionReconciler) handleFinalizer(ctx context.Context, o *secretsv1alpha1.VaultConnection) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultConnectionFinalizer) {
		opts := cacheEvictionOption{
			filterFunc: filterAllCacheRefs,
			matchingLabels: client.MatchingLabels{
				"vaultConnectionRef":          o.GetName(),
				"vaultConnectionRefNamespace": o.GetNamespace(),
			},
		}
		_, err := evictClientCacheRefs(ctx, r.Client, o, r.Recorder, opts)
		if err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
				"Failed to evict referent VaultCacheClient resources: %s", err)
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
		For(&secretsv1alpha1.VaultConnection{}).
		WithEventFilter(ignoreUpdatePredicate()).
		Complete(r)
}
