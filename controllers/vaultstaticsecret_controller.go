// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
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
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.ClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

func (r *VaultStaticSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1alpha1.VaultStaticSecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", o)
		return ctrl.Result{}, err
	}

	spec := o.Spec

	sec1 := &corev1.Secret{}
	if err := r.Client.Get(ctx,
		types.NamespacedName{
			Namespace: o.Namespace,
			Name:      spec.Dest,
		},
		sec1,
	); err != nil {
		return ctrl.Result{}, err
	}

	c, err := r.ClientFactory.GetClient(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault auth login: %s", err)
		return ctrl.Result{}, err
	}

	var refAfter time.Duration
	if spec.RefreshAfter != "" {
		d, err := time.ParseDuration(spec.RefreshAfter)
		if err != nil {
			logger.Error(err, "Failed to parse spec.RefreshAfter")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Failed to parse spec.RefreshAfter %s", spec.RefreshAfter)
			return ctrl.Result{}, err
		}
		refAfter = d
	}

	var resp *api.KVSecret
	switch spec.Type {
	case "kv-v1":
		w, err := c.KVv1(spec.Mount)
		if err != nil {
			return ctrl.Result{}, err
		}
		resp, err = w.Get(ctx, spec.Name)
	case "kv-v2":
		w, err := c.KVv2(spec.Mount)
		if err != nil {
			return ctrl.Result{}, err
		}
		resp, err = w.Get(ctx, spec.Name)
	default:
		err = fmt.Errorf("unsupported secret type %q", spec.Type)
		logger.Error(err, "")
		r.Recorder.Event(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret, err.Error())
		return ctrl.Result{}, err
	}
	if err != nil {
		logger.Error(err, "Failed to read Vault secret")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to read Vault secret: %s", err)
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, nil
	}

	if resp == nil {
		logger.Error(nil, "empty Vault secret", "mount", spec.Mount, "name", spec.Name)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Vault secret was empty, mount %s, name %s", spec.Mount, spec.Name)
		return ctrl.Result{
			RequeueAfter: refAfter,
		}, nil
	}

	if sec1.Data, err = makeK8sSecret(resp); err != nil {
		logger.Error(err, "Failed to construct k8s secret")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to construct k8s secret: %s", err)
		return ctrl.Result{}, err
	}

	if err := r.Client.Update(ctx, sec1); err != nil {
		logger.Error(err, "Failed to update k8s secret")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
			"Failed to update k8s secret %s/%s: %s", sec1.ObjectMeta.Namespace,
			sec1.ObjectMeta.Name, err)
		return ctrl.Result{}, err
	}

	r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonAccepted, "Secret synced")
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

func makeK8sSecret(vaultSecret *api.KVSecret) (map[string][]byte, error) {
	if vaultSecret.Raw == nil {
		return nil, fmt.Errorf("raw portion of vault secret was nil")
	}

	b, err := json.Marshal(vaultSecret.Raw.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal raw Vault secret: %s", err)
	}
	k8sSecretData := map[string][]byte{
		"_raw": b,
	}
	for k, v := range vaultSecret.Data {
		if k == "_raw" {
			return nil, fmt.Errorf("key '_raw' not permitted in Vault secret")
		}
		var m []byte
		switch vTyped := v.(type) {
		case string:
			m = []byte(vTyped)
		default:
			m, err = json.Marshal(vTyped)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal key %q from Vault secret: %s", k, err)
			}
		}
		k8sSecretData[k] = m
	}
	return k8sSecretData, nil
}
