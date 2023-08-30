// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/client/secret_service"
	hcpconfig "github.com/hashicorp/hcp-sdk-go/config"
	hcpclient "github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/hashicorp/vault-secrets-operator/internal/credentials"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

// HCPVaultSecretsAppReconciler reconciles a HCPVaultSecretsApp object
type HCPVaultSecretsAppReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	HMACValidator helpers.HMACValidator
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *HCPVaultSecretsAppReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.HCPVaultSecretsApp{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", o)
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

	// we want to ensure that requeueAfter is set so that we can perform the proper
	// drift detection during each reconciliation. setting up a watcher on the Secret
	// is also possibility, but polling seems to be the simplest approach for now.
	if requeueAfter == 0 {
		// hardcoding a default horizon here, perhaps we will want to make this value public?
		requeueAfter = computeHorizonWithJitter(time.Second * 60)
	}

	c, err := r.secretClient(ctx, o)
	if err != nil {
		logger.Error(err, "Get HCP Client")
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	params := &hvsclient.OpenAppSecretsParams{
		Context: ctx,
		AppName: o.Spec.AppName,
	}

	resp, err := c.OpenAppSecrets(params, nil)
	if err != nil {
		logger.Error(err, "Get App Secret", "appName", o.Spec.AppName)
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	s := resp.GetPayload()
	data := make(map[string][]byte)
	b, err := s.MarshalBinary()
	if err != nil {
		logger.Error(err, "Secrets.MarshalBinary()", "appName", o.Spec.AppName)
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	data["_raw"] = b
	for _, v := range s.Secrets {
		ver := v.Version
		if ver.Type != "kv" {
			logger.V(consts.LogLevelWarning).Info("Unsupported secret type",
				"type", ver.Type, "name", v.Name)
			continue
		}
		data[v.Name] = []byte(ver.Value)
	}

	doRolloutRestart := o.Status.SecretMAC != ""
	// doRolloutRestart only if this is not the first time this secret has been synced
	macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.Client, r.HMACValidator, o, data)
	if err != nil {
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)

	syncSecret := !macsEqual
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

// SetupWithManager sets up the controller with the Manager.
func (r *HCPVaultSecretsAppReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.HCPVaultSecretsApp{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *HCPVaultSecretsAppReconciler) secretClient(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp) (hvsclient.ClientService, error) {
	authObj, err := common.GetHCPAuthForObj(ctx, r.Client, o)
	if err != nil {
		return nil, fmt.Errorf("failed to get HCPAuth, err=%w", err)
	}

	p, err := credentials.NewCredentialProvider(ctx, r.Client, authObj, o.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to setup CredentialProvider, err=%w", err)
	}

	creds, err := p.GetCreds(ctx, r.Client)
	if err != nil {
		return nil, fmt.Errorf("failed to get creds from CredentialProvider, err=%w", err)
	}

	hcpConfig, err := hcpconfig.NewHCPConfig(
		hcpconfig.WithProfile(&profile.UserProfile{
			OrganizationID: authObj.Spec.OrganizationID,
			ProjectID:      authObj.Spec.ProjectID,
		}),
		hcpconfig.WithClientCredentials(
			creds["clientID"].(string), creds["clientKey"].(string),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get HCP Config, err=%w", err)
	}
	cl, err := hcpclient.New(hcpclient.Config{
		HCPConfig: hcpConfig,
	})
	hc := hvsclient.New(cl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get HCP Client, err=%w", err)
	}

	return hc, nil
}
