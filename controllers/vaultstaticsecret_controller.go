// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultStaticSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *VaultStaticSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	var s secretsv1alpha1.VaultStaticSecret
	if err := r.Client.Get(ctx, req.NamespacedName, &s); err != nil {
		if apierrors.IsNotFound(err) {
			// TODO: delete the secret?
			return ctrl.Result{}, nil
		}

		l.Error(err, "error getting resource from k8s", "secret", s)
		return ctrl.Result{}, err
	}

	spec := s.Spec

	if spec.Type != "kvv2" {
		err := fmt.Errorf("unsupported secret type %q", spec.Type)
		l.Error(err, "")
		return ctrl.Result{}, err
	}

	sec1 := &corev1.Secret{}
	if err := r.Client.Get(ctx,
		types.NamespacedName{
			Namespace: s.Namespace,
			Name:      spec.Dest,
		},
		sec1,
	); err != nil {
		return ctrl.Result{}, err
	}

	l.Info(fmt.Sprintf("%#v", sec1))

	vc, err := getVaultConfig(ctx, r.Client, types.NamespacedName{Namespace: s.Namespace, Name: s.Spec.VaultAuthRef})
	if err != nil {
		return ctrl.Result{}, err
	}

	c, err := getVaultClient(ctx, vc, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	if _, err = c.Sys().SealStatus(); err != nil {
		l.Error(err, "error getting Vault status")
		return ctrl.Result{}, err
	}

	// status, _ := c.Sys().SealStatus()
	// l.Info(fmt.Sprintf("Vault seal status %#v", status))

	var refAfter time.Duration
	if spec.RefreshAfter != "" {
		d, err := time.ParseDuration(spec.RefreshAfter)
		if err != nil {
			l.Error(err, "failed to parse spec.RefreshAfter")
			return ctrl.Result{}, err
		}
		refAfter = d
	}

	path := r.getKVV2Path(spec.Mount, spec.Name)
	l.Info(fmt.Sprintf("Read it :) %q", path), "secret", s)
	resp, err := c.Logical().Read(path)
	if err != nil {
		l.Error(err, "error reading secret %q")
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, err
	}

	if resp == nil {
		l.Error(err, "empty Vault secret", "path", path)
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, err
	}

	l.Info(fmt.Sprintf("Resp %#v", resp))

	b, err := json.Marshal(resp.Data)
	sec1.Data = map[string][]byte{
		"data": b,
	}
	if err := r.Client.Update(ctx, sec1); err != nil {
		l.Error(err, "error reading secret %q")
		return ctrl.Result{}, err
	}

	// TODO:
	// - store KV in a k8s secret
	// - support deletion
	// - support app webhook registration for rotation signalling
	// - add support for db creds, to demo dynamic credential rotation
	// - prepare single slide for Weds.

	// set ctrl.Result.Requeue to true with RequeueAfter being the credential (expiry TTL - some offset)
	return ctrl.Result{
		RequeueAfter: refAfter,
	}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultStaticSecret{}).
		Complete(r)
}

func (r *VaultStaticSecretReconciler) getKVV2Path(mount, name string) string {
	return joinPath(mount, "data", name)
}

func joinPath(parts ...string) string {
	return strings.Join(parts, "/")
}
