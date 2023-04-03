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

const vaultKubernetesAuthBackendRoleFinalizer = "vaultkubernetesauthbackend.secrets.hashicorp.com/finalizer"

// VaultKubernetesAuthBackendRoleReconciler reconciles a VaultKubernetesAuthBackendRole object
type VaultKubernetesAuthBackendRoleReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.ClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultkubernetesauthbackendroles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultkubernetesauthbackendroles/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultkubernetesauthbackendroles/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *VaultKubernetesAuthBackendRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1alpha1.VaultKubernetesAuthBackendRole{}
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

	_, err = c.Write(ctx, fmt.Sprintf("/auth/%s/role/%s", o.Spec.Path, o.Spec.Name), map[string]interface{}{
		"audience":                         o.Spec.Audience,
		"alias_name_source":                o.Spec.AliasNameSource,
		"bound_service_account_names":      o.Spec.BoundServiceAccountNames,
		"bound_service_account_namespaces": o.Spec.BoundServiceAccountNamespaces,
		"token_ttl":                        o.Spec.TokenTTL,
		"token_max_ttl":                    o.Spec.TokenMaxTTL,
		"policies":                         o.Spec.Policies,
		"token_bound_cidrs":                o.Spec.TokenBoundCIDRs,
		"token_explicit_max_ttl":           o.Spec.TokenExplicitMaxTTL,
		"token_no_default_policy":          o.Spec.TokenNoDefaultPolicy,
		"token_num_uses":                   o.Spec.TokenNumUses,
		"token_period":                     o.Spec.TokenPeriod,
		"token_type":                       o.Spec.TokenType,
	})

	if err != nil {
		return ctrl.Result{}, err
	}

	if o.Status.Path != "" && o.Status.Path != o.Spec.Path {
		if _, err := c.Delete(ctx, o.Status.Path); err != nil {
			return ctrl.Result{}, err
		}
	}

	o.Status.Valid = true
	o.Status.Path = o.Spec.Path

	if err := r.Status().Update(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *VaultKubernetesAuthBackendRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultKubernetesAuthBackendRole{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *VaultKubernetesAuthBackendRoleReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultKubernetesAuthBackendRole) error {
	if !controllerutil.ContainsFinalizer(o, vaultKubernetesAuthBackendRoleFinalizer) {
		controllerutil.AddFinalizer(o, vaultKubernetesAuthBackendRoleFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}

	return nil
}

func (r *VaultKubernetesAuthBackendRoleReconciler) handleFinalizer(ctx context.Context, c vault.Client, o *secretsv1alpha1.VaultKubernetesAuthBackendRole) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultKubernetesAuthBackendRoleFinalizer) {
		if _, err := c.Delete(ctx, o.Spec.Path); err != nil {
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(o, vaultKubernetesAuthBackendRoleFinalizer)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}
