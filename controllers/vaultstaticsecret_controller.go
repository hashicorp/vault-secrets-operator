// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault/api"
)

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get

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

	vc, err := getVaultConfig(ctx, r.Client, types.NamespacedName{Namespace: s.Namespace, Name: s.Spec.VaultAuthRef})
	if err != nil {
		l.Error(err, "error getting Vault config")
		return ctrl.Result{}, err
	}

	c, err := getVaultClient(ctx, vc, r.Client)
	if err != nil {
		l.Error(err, "error getting Vault client")
		return ctrl.Result{}, err
	}
	if _, err = c.Sys().SealStatusWithContext(ctx); err != nil {
		l.Error(err, "Failed to check Vault seal status")
		r.Recorder.Eventf(&s, corev1.EventTypeWarning, reasonVaultClientError, "Failed to check Vault seal status: %s", err)
		return ctrl.Result{}, err
	}

	var refAfter time.Duration
	if spec.RefreshAfter != "" {
		d, err := time.ParseDuration(spec.RefreshAfter)
		if err != nil {
			l.Error(err, "Failed to parse spec.RefreshAfter")
			r.Recorder.Eventf(&s, corev1.EventTypeWarning, reasonVaultStaticSecret, "Failed to parse spec.RefreshAfter %s", spec.RefreshAfter)
			return ctrl.Result{}, err
		}
		refAfter = d
	}

	var resp *api.KVSecret
	switch spec.Type {
	case "kvv2", "kv-v2":
		resp, err = c.KVv2(spec.Mount).Get(ctx, spec.Name)
	case "kv", "kvv1", "kv-v1":
		resp, err = c.KVv1(spec.Mount).Get(ctx, spec.Name)
	default:
		err := fmt.Errorf("unsupported secret type %q", spec.Type)
		l.Error(err, "")
		r.Recorder.Event(&s, corev1.EventTypeWarning, reasonVaultStaticSecret, err.Error())
		return ctrl.Result{}, err
	}
	if err != nil {
		l.Error(err, "error reading secret %q")
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, nil
	}

	if resp == nil {
		l.Error(err, "empty Vault secret", "mount", spec.Mount, "name", spec.Name)
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, nil
	}

	b, err := json.Marshal(resp.Raw.Data)
	if err != nil {
		l.Error(err, "Failed to marshal resp.Data")
	}
	sec1.Data = map[string][]byte{
		"_raw": b,
	}
	for k, v := range resp.Data {
		var m []byte
		switch vTyped := v.(type) {
		case string:
			m = []byte(vTyped)
		default:
			m, err = json.Marshal(vTyped)
			if err != nil {
				l.Error(err, "Failed to marshal Vault secret", "secret name", spec.Name, "key", k)
				continue
			}
		}
		sec1.Data[k] = m
	}
	if err := r.Client.Update(ctx, sec1); err != nil {
		l.Error(err, "Failed to update secret %q")
		return ctrl.Result{}, err
	}

	// set ctrl.Result.Requeue to true with RequeueAfter being the credential (expiry TTL - some offset)
	return ctrl.Result{
		RequeueAfter: refAfter,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultStaticSecret{}).
		Complete(r)
}
