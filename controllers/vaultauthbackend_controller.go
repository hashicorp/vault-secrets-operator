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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultAuthBackendFinalizer = "vaultauthbackend.secrets.hashicorp.com/finalizer"

// VaultAuthBackendReconciler reconciles a VaultAuthBackend object
type VaultAuthBackendReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.ClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthbackends,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthbackends/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauthbackends/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *VaultAuthBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1alpha1.VaultAuthBackend{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "backend", o)
		return ctrl.Result{}, err
	}

	c, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault auth login: %s", err)
		return ctrl.Result{}, err
	}

	o.Status.Valid = false

	if o.GetDeletionTimestamp() == nil {
		if err := r.addFinalizer(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Got deletion timestamp", "obj", o)
		return r.handleFinalizer(ctx, c, o)
	}

	path, err := c.Read(ctx, fmt.Sprintf("/sys/auth/%s", o.Spec.Path))
	if err != nil {
		return ctrl.Result{}, err
	}

	if path == nil {
		_, err = c.Write(ctx, fmt.Sprintf("/sys/auth/%s", o.Spec.Path), map[string]interface{}{
			"description": o.Spec.Description,
			"type":        o.Spec.Type,
		})

		if err != nil {
			return ctrl.Result{}, err
		}

		if o.Status.Path != "" && o.Status.Path != o.Spec.Path {
			if _, err := c.Delete(ctx, fmt.Sprintf("/sys/auth/%s", o.Status.Path)); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	o.Status.Valid = true
	o.Status.Path = o.Spec.Path

	if err := r.Status().Update(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *VaultAuthBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultAuthBackend{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *VaultAuthBackendReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultAuthBackend) error {
	if !controllerutil.ContainsFinalizer(o, vaultAuthBackendFinalizer) {
		controllerutil.AddFinalizer(o, vaultAuthBackendFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}

	return nil
}

func (r *VaultAuthBackendReconciler) handleFinalizer(ctx context.Context, c vault.Client, o *secretsv1alpha1.VaultAuthBackend) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultAuthBackendFinalizer) {
		if _, err := c.Delete(ctx, o.Spec.Path); err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(o, vaultAuthBackendFinalizer)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}
