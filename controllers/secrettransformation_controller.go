// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

// SecretTransformationReconciler reconciles a SecretTransformation object
type SecretTransformationReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the SecretTransformation object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *SecretTransformationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	o, err := common.GetSecretTransformation(ctx, r.Client, req.NamespacedName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get SecretTransformation resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		metrics.DeleteResourceStatus("secrettransformation", o)
		return ctrl.Result{}, nil
	}

	o.Status.Valid = pointer.Bool(true)
	o.Status.Error = ""
	errs := ValidateSecretTransformation(ctx, o)
	if errs != nil {
		o.Status.Valid = pointer.Bool(false)
		o.Status.Error = errs.Error()
		logger.Error(err, "Failed to validate configured templates")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonInvalidConfiguration,
			"Failed to validate configured templates: %s", errs)
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SecretTransformationReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.SecretTransformation) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("secrettransformation", o, pointer.BoolDeref(o.Status.Valid, false))
	if err := r.Status().Update(ctx, o); err != nil {
		logger.Error(err, "Failed to update the resource's status")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretTransformationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.SecretTransformation{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
