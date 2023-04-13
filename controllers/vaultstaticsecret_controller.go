// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Recorder        record.EventRecorder
	ClientFactory   vault.ClientFactory
	HMACFunc        vault.HMACFromSecretFunc
	ValidateMACFunc vault.ValidateMACFromSecretFunc
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//
// required for rollout-restart
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
//

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

	c, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault auth login: %s", err)
		return ctrl.Result{}, err
	}

	var requeueAfter time.Duration
	if o.Spec.RefreshAfter != "" {
		d, err := time.ParseDuration(o.Spec.RefreshAfter)
		if err != nil {
			logger.Error(err, "Failed to parse o.Spec.RefreshAfter")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Failed to parse o.Spec.RefreshAfter %s", o.Spec.RefreshAfter)
			return ctrl.Result{}, err
		}
		requeueAfter = computeHorizonWithJitter(d)
	}

	var resp *api.KVSecret
	switch o.Spec.Type {
	case consts.KVSecretTypeV1:
		w, err := c.KVv1(o.Spec.Mount)
		if err != nil {
			return ctrl.Result{}, err
		}
		resp, err = w.Get(ctx, o.Spec.Name)
	case consts.KVSecretTypeV2:
		w, err := c.KVv2(o.Spec.Mount)
		if err != nil {
			return ctrl.Result{}, err
		}
		resp, err = w.Get(ctx, o.Spec.Name)
	default:
		err = fmt.Errorf("unsupported secret type %q", o.Spec.Type)
		logger.Error(err, "")
		r.Recorder.Event(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret, err.Error())
		return ctrl.Result{}, err
	}

	if err != nil {
		logger.Error(err, "Failed to read Vault secret")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to read Vault secret: %s", err)
		return ctrl.Result{}, nil
	}

	if resp == nil {
		logger.Error(nil, "empty Vault secret", "mount", o.Spec.Mount, "name", o.Spec.Name)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Vault secret was empty, mount %s, name %s", o.Spec.Mount, o.Spec.Name)
		return ctrl.Result{
			RequeueAfter: requeueAfter,
		}, nil
	}

	data, err := makeK8sSecret(resp)
	if err != nil {
		logger.Error(err, "Failed to construct k8s secret")
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to construct k8s secret: %s", err)
		return ctrl.Result{}, err
	}

	var doRolloutRestart bool
	syncSecret := true
	if o.Spec.HMACSecretData {
		// we want to ensure that requeueAfter is set so that we can perform the proper drift detection during each reconciliation.
		// setting up a watcher on the Secret is also possibility, but polling seems to be the simplest approach for now.
		if requeueAfter == 0 {
			// hardcoding a default horizon here, perhaps we will want make this value public?
			requeueAfter = computeHorizonWithJitter(time.Second * 60)
		}

		// doRolloutRestart only if this is not the first time this secret has been synced
		doRolloutRestart = o.Status.SecretMAC != ""

		macsEqual, messageMAC, err := r.handleSecretHMAC(ctx, o, data)
		if err != nil {
			return ctrl.Result{}, err
		}

		syncSecret = !macsEqual

		o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)
	} else if len(o.Spec.RolloutRestartTargets) > 0 {
		logger.V(consts.LogLevelWarning).Info("Ignoring RolloutRestartTargets",
			"hmacSecretData", o.Spec.HMACSecretData,
			"targets", o.Spec.RolloutRestartTargets)
	}

	if syncSecret {
		if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
				"Failed to update k8s secret: %s", err)
			return ctrl.Result{}, err
		}
		reason := consts.ReasonSecretSynced
		if doRolloutRestart {
			reason = consts.ReasonSecretRotated
			// rollout-restart errors are not retryable
			// all error reporting is handled by helpers.HandleRolloutRestarts
			_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
		}
		r.Recorder.Event(o, corev1.EventTypeNormal, reason, "Secret synced")
	} else {
		r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonSecretSync, "Secret sync not required")
	}

	if err := r.Status().Update(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

// handleSecretHMAC compares the HMAC of data to its previously computed value stored in o.Status.SecretHMAC,
// returning true if they are equal. The computed new-MAC will be returned so that o.Status.SecretHMAC can be updated.
func (r *VaultStaticSecretReconciler) handleSecretHMAC(ctx context.Context, o *secretsv1alpha1.VaultStaticSecret, data map[string][]byte) (bool, []byte, error) {
	logger := log.FromContext(ctx)

	// HMAC the Vault secret data so that it can be compared to the what's in the destination Secret.
	message, err := json.Marshal(data)
	if err != nil {
		return false, nil, err
	}

	newMAC, err := r.HMACFunc(ctx, r.Client, message)
	if err != nil {
		return false, nil, err
	}

	// we have never computed the Vault secret data HMAC,
	// so there is no need to perform Secret data drift detection.
	if o.Status.SecretMAC == "" {
		return false, newMAC, nil
	}

	lastMAC, err := base64.StdEncoding.DecodeString(o.Status.SecretMAC)
	if err != nil {
		return false, nil, err
	}

	macsEqual := vault.EqualMACS(lastMAC, newMAC)
	if macsEqual {
		// check to see if the Secret.Data has drifted since the last sync,
		// if it has then it will be overwritten with the Vault secret data
		// this would indicate an out-of-band change made to the Secret's data
		// in this case the controller should do the sync.
		if cur, ok, _ := helpers.GetSecret(ctx, r.Client, o); ok {
			curMessage, err := json.Marshal(cur.Data)
			if err != nil {
				return false, nil, err
			}

			logger.V(consts.LogLevelDebug).Info("Doing Secret data drift detection", "lastMAC", lastMAC)
			// we only care of the MAC has changed, it's new value is not important here.
			valid, foundMAC, err := r.ValidateMACFunc(ctx, r.Client, curMessage, lastMAC)
			if err != nil {
				return false, nil, err
			}
			if !valid {
				logger.V(consts.LogLevelDebug).Info("Secret data drift detected",
					"lastMAC", lastMAC, "foundMAC", foundMAC, "curMessage", curMessage, "message", message)
			}

			macsEqual = valid
		} else {
			macsEqual = false
		}
	}

	return macsEqual, newMAC, nil
}

// SetupWithManager sets up the controller with the Manager.
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

func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultStaticSecret{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
