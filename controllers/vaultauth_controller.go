// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
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
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the VaultAuth object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
func (r *VaultAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	a, err := getVaultAuth(ctx, r.Client, req.NamespacedName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultAuth resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// ensure that the vaultConnectionRef is set for any VaultAuth resource in the operator namespace.
	if a.Namespace == operatorNamespace && a.Spec.VaultConnectionRef == "" {
		err := fmt.Errorf("vaultConnectionRef must be set on resources in the %q namespace", operatorNamespace)
		logger.Error(err, "Invalid resource")
		a.Status.Valid = false
		a.Status.Error = err.Error()
		logger.Error(err, a.Status.Error)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	connName, err := getConnectionNamespacedName(a)
	if err != nil {
		a.Status.Valid = false
		a.Status.Error = reasonInvalidResourceRef
		msg := "Invalid vaultConnectionRef"
		logger.Error(err, msg)
		r.recordEvent(a, a.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if _, err := getVaultConnection(ctx, r.Client, connName); err != nil {
		a.Status.Valid = false
		if apierrors.IsNotFound(err) {
			a.Status.Error = reasonConnectionNotFound
		} else {
			a.Status.Error = reasonInvalidConnection
		}

		msg := "Failed getting the VaultConnection resource"
		logger.Error(err, msg)
		r.recordEvent(a, a.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, a); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if _, err := vault.NewAuthLogin(r.Client, a, a.Namespace); err != nil {
		a.Status.Valid = false
		a.Status.Error = reasonInvalidAuthConfiguration
		msg := "Failed to get a valid AuthLogin, this is most likely a bug in the operator!"
		logger.Error(err, msg)
		r.recordEvent(a, a.Status.Error, msg+": %s", err)
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

	msg := "Successfully handled VaultAuth resource request"
	logger.Info(msg)
	r.recordEvent(a, reasonAccepted, msg)

	return ctrl.Result{}, nil
}

func (r *VaultAuthReconciler) recordEvent(a *secretsv1alpha1.VaultAuth, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !a.Status.Valid {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(a, eventType, reason, msg, i...)
}

func (r *VaultAuthReconciler) updateStatus(ctx context.Context, a *secretsv1alpha1.VaultAuth) error {
	logger := log.FromContext(ctx)
	logger.Info("Updating status", "status", a.Status)
	metrics.SetResourceStatus("vaultauth", a, a.Status.Valid)
	if err := r.Status().Update(ctx, a); err != nil {
		msg := "Failed to update the resource's status"
		r.recordEvent(a, reasonStatusUpdateError, "%s: %s", msg, err)
		logger.Error(err, msg)
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
