// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// VaultAuthReconciler reconciles a VaultAuth object
type VaultAuthReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=get;list;create;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the VaultAuth object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *VaultAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	// TODO: add telemetry support

	a, err := getVaultAuth(ctx, r.Client, req.NamespacedName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed getting resource from k8s", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	n, err := a.GetConnectionNamespacedName()
	if err != nil {
		a.Status.Valid = false
		a.Status.Error = "Invalid resource"
		logger.Error(err, a.Status.Error)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if _, err := getVaultConnection(ctx, r.Client, n); err != nil {
		a.Status.Valid = false
		a.Status.Error = "No VaultConnection configured"
		logger.Error(err, a.Status.Error)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if _, err := vault.NewAuthLogin(r.Client, a, a.Namespace); err != nil {
		a.Status.Valid = false
		a.Status.Error = "Invalid auth configuration"
		logger.Error(err, a.Status.Error)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	a.Status.Valid = true
	a.Status.Error = ""
	if err := r.updateStatus(ctx, a); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Valid request")

	return ctrl.Result{}, nil
}

func (r *VaultAuthReconciler) updateStatus(ctx context.Context, a *secretsv1alpha1.VaultAuth) error {
	logger := log.FromContext(ctx)
	logger.Info("Updating status", "status", a.Status)
	g := resourceStatus.WithLabelValues("vaultauth", a.Name, a.Namespace)
	if !a.Status.Valid {
		g.Set(float64(1))
	} else {
		g.Set(float64(0))
	}
	if err := r.Status().Update(ctx, a); err != nil {
		logger.Error(err, "Failed to update the status")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultAuth{}).
		WithEventFilter(ignoreUpdatePredicate()).
		Complete(r)
}

func (r *VaultAuthReconciler) InitMetrics() {
	metrics.Registry.MustRegister(
		resourceStatus,
	)
}
