// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/go-multierror"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

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
	l := log.FromContext(ctx)

	var c secretsv1alpha1.VaultConnection
	if err := r.Client.Get(ctx, req.NamespacedName, &c); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		l.Error(err, "Failed to retrieve resource from k8s", "connection", c)
		return ctrl.Result{}, err
	}
	defer func() {
		if updateErr := r.Client.Status().Update(ctx, &c); updateErr != nil {
			l.Error(updateErr, "Failed to update VaultConnection status", "new status", c.Status)
			// add the update error to the returned err from Reconcile
			err = multierror.Append(err, updateErr)
		}
	}()

	vaultConfig := &vault.VaultClientConfig{
		CACertSecretRef: c.Spec.CACertSecretRef,
		K8sNamespace:    c.ObjectMeta.Namespace,
		Address:         c.Spec.Address,
		SkipTLSVerify:   c.Spec.SkipTLSVerify,
		TLSServerName:   c.Spec.TLSServerName,
	}
	vaultClient, err := vault.MakeVaultClient(ctx, vaultConfig, r.Client)
	if err != nil {
		c.Status.Valid = false
		l.Error(err, "Failed to construct Vault client")
		r.Recorder.Eventf(&c, corev1.EventTypeWarning, reasonVaultClientError, "Failed to construct Vault client: %s", err)
		return ctrl.Result{}, err
	}

	if _, err := vaultClient.Sys().SealStatusWithContext(ctx); err != nil {
		c.Status.Valid = false
		l.Error(err, "Failed to check Vault seal status, requeuing")
		r.Recorder.Eventf(&c, corev1.EventTypeWarning, "VaultClientError", "Failed to check Vault seal status: %s", err)
		return ctrl.Result{}, err
	}

	c.Status.Valid = true

	r.Recorder.Event(&c, corev1.EventTypeNormal, reasonAccepted, "VaultConnection accepted")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultConnection{}).
		Complete(r)
}
