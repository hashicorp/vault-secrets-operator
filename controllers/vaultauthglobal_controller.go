// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

// VaultAuthGlobalReconciler reconciles a VaultAuthGlobal object
type VaultAuthGlobalReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthglobals,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthglobals/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthglobals/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *VaultAuthGlobalReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultAuthGlobalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultAuthGlobal{}).
		Complete(r)
}
