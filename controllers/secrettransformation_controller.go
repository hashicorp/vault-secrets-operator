// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/template"
)

// SecretTransformationReconciler reconciles a SecretTransformation object
type SecretTransformationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=secrettransformations/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

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

	o.Status.Valid = true

	var errs error
	stmpl := template.NewSecretTemplate(o.Name)
	for idx, tmpl := range o.Spec.SourceTemplates {
		name := tmpl.Name
		if name == "" {
			name = fmt.Sprintf("%s/%d", client.ObjectKeyFromObject(o), idx)
		}
		if err := stmpl.Parse(name, tmpl.Text); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	for _, tmpl := range o.Spec.Templates {
		if err := stmpl.Parse(tmpl.Name, tmpl.Text); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	o.Status.Valid = true
	o.Status.Error = ""
	if errs != nil {
		o.Status.Valid = false
		o.Status.Error = errs.Error()
		logger.Error(err, "Failed to validate template specs")
	}

	if o.Status.Valid {
		// TODO: force reconcile all syncable secrets that reference this SecretTransformation
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *SecretTransformationReconciler) updateStatus(ctx context.Context, a *secretsv1beta1.SecretTransformation) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("secrettransformation", a, a.Status.Valid)
	if err := r.Status().Update(ctx, a); err != nil {
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
