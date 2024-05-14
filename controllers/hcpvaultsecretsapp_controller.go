// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/client/secret_service"
	hcpconfig "github.com/hashicorp/hcp-sdk-go/config"
	hcpclient "github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/hcp"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/version"
)

const (
	headerHVSRequester = "X-HVS-Requester"
	headerUserAgent    = "User-Agent"

	hcpVaultSecretsAppFinalizer = "hcpvaultsecretsapp.secrets.hashicorp.com/finalizer"
)

var userAgent = fmt.Sprintf("vso/%s", version.Version().String())

// HCPVaultSecretsAppReconciler reconciles a HCPVaultSecretsApp object
type HCPVaultSecretsAppReconciler struct {
	client.Client
	Scheme                     *runtime.Scheme
	Recorder                   record.EventRecorder
	SecretDataBuilder          *helpers.SecretDataBuilder
	HMACValidator              helpers.HMACValidator
	MinRefreshAfter            time.Duration
	referenceCache             ResourceReferenceCache
	GlobalTransformationOption *helpers.GlobalTransformationOption
	BackOffRegistry            *BackOffRegistry
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//
// required for rollout-restart
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
//

// Reconcile a secretsv1beta1.HCPVaultSecretsApp Custom Resource instance. Each
// invocation will ensure that the configured HCP Vault Secrets Application data
// is synced to the configured K8s Secret.
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

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		return ctrl.Result{}, r.handleDeletion(ctx, o)
	}

	var requeueAfter time.Duration
	if o.Spec.RefreshAfter != "" {
		d, err := parseDurationString(o.Spec.RefreshAfter, ".spec.refreshAfter", r.MinRefreshAfter)
		if err != nil {
			logger.Error(err, "Field validation failed")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Field validation failed, err=%s", err)
			return ctrl.Result{}, err
		}
		if d.Seconds() > 0 {
			requeueAfter = computeHorizonWithJitter(d)
		}
	}

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	c, err := r.hvsClient(ctx, o)
	if err != nil {
		logger.Error(err, "Get HCP Vault Secrets Client")
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
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	data, err := r.SecretDataBuilder.WithHVSAppSecrets(resp, transOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretDataBuilderError,
			"Failed to build K8s secret data: %s", err)
		logger.Error(err, "Failed to build K8s Secret data", "appName", o.Spec.AppName)
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	doSync := true
	// doRolloutRestart only if this is not the first time this secret has been synced
	doRolloutRestart := o.Status.SecretMAC != ""
	macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.Client, r.HMACValidator, o, data)
	if err != nil {
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	// skip the next sync if the data has not changed since the last sync, and the
	// resource has not been updated.
	// Note: spec.status.lastGeneration was added later, so we don't want to force a
	// sync until we've updated it.
	if o.Status.LastGeneration == 0 || o.Status.LastGeneration == o.GetGeneration() {
		doSync = !macsEqual
	}

	o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)
	if doSync {
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

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *HCPVaultSecretsAppReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp) error {
	o.Status.LastGeneration = o.GetGeneration()
	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, hcpVaultSecretsAppFinalizer)
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *HCPVaultSecretsAppReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = newResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.HCPVaultSecretsApp{}).
		WithEventFilter(syncableSecretPredicate(nil)).
		WithOptions(opts).
		Watches(
			&secretsv1beta1.SecretTransformation{},
			NewEnqueueRefRequestsHandlerST(r.referenceCache, nil),
		).
		Watches(
			&corev1.Secret{},
			&enqueueOnDeletionRequestHandler{
				gvk: secretsv1beta1.GroupVersion.WithKind(HCPVaultSecretsApp.String()),
			},
			builder.WithPredicates(&secretsPredicate{}),
		).
		Complete(r)
}

func (r *HCPVaultSecretsAppReconciler) hvsClient(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp) (hvsclient.ClientService, error) {
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
			creds[hcp.ProviderSecretClientID].(string),
			creds[hcp.ProviderSecretClientSecret].(string),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate HCP Config, err=%w", err)
	}

	cl, err := hcpclient.New(hcpclient.Config{
		HCPConfig: hcpConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate HCP Client, err=%w", err)
	}

	injectRequestInformation(cl)

	return hvsclient.New(cl, nil), nil
}

func (r *HCPVaultSecretsAppReconciler) handleDeletion(ctx context.Context, o client.Object) error {
	logger := log.FromContext(ctx)
	objKey := client.ObjectKeyFromObject(o)
	r.referenceCache.Remove(SecretTransformation, objKey)
	r.BackOffRegistry.Delete(objKey)
	if controllerutil.ContainsFinalizer(o, hcpVaultSecretsAppFinalizer) {
		logger.Info("Removing finalizer")
		if controllerutil.RemoveFinalizer(o, hcpVaultSecretsAppFinalizer) {
			if err := r.Update(ctx, o); err != nil {
				logger.Error(err, "Failed to remove the finalizer")
				return err
			}
			logger.Info("Successfully removed the finalizer")
		}
	}
	return nil
}

// transport is copied from https://github.com/hashicorp/vlt/blob/f1f50c53433aa1c6dd0e7f0f929553bb4e5d2c63/internal/command/transport.go#L15
type transport struct {
	child http.RoundTripper
}

// RoundTrip is a wrapper implementation of the http.RoundTrip interface to
// inject a header for identifying the requester type
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add(headerUserAgent, userAgent)
	req.Header.Add(headerHVSRequester, userAgent)
	return t.child.RoundTrip(req)
}

// injectRequestInformation is copied from https://github.com/hashicorp/vlt/blob/f1f50c53433aa1c6dd0e7f0f929553bb4e5d2c63/internal/command/transport.go#L25
func injectRequestInformation(runtime *httptransport.Runtime) {
	runtime.Transport = &transport{child: runtime.Transport}
}
