// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	hcpconfig "github.com/hashicorp/hcp-sdk-go/config"
	hcpclient "github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/credentials"
	"github.com/hashicorp/vault-secrets-operator/credentials/hcp"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/version"
)

const (
	headerHVSRequester = "X-HVS-Requester"
	headerUserAgent    = "User-Agent"

	hcpVaultSecretsAppFinalizer = "hcpvaultsecretsapp.secrets.hashicorp.com/finalizer"

	// defaultDynamicRenewPercent is the default renewal point in the dynamic
	// secret's TTL, expressed as a percent out of 100
	defaultDynamicRenewPercent = 67

	// defaultDynamicRequeue is for use when a dynamic secret needs to be
	// renewed ASAP so we need a requeue time that's not zero
	defaultDynamicRequeue = 1 * time.Second
)

var (
	userAgent = fmt.Sprintf("vso/%s", version.Version().String())
	// hvsErrorRe is a regexp to parse the error message from the HVS API
	// The error message is expected to be in the format:
	// [METHOD PATH_PATTERN][STATUS_CODE]
	hvsErrorRe = regexp.MustCompile(`\[(\w+) (.+)\]\[(\d+)\]`)
)

// HCPVaultSecretsAppReconciler reconciles a HCPVaultSecretsApp object
type HCPVaultSecretsAppReconciler struct {
	client.Client
	Scheme                      *runtime.Scheme
	Recorder                    record.EventRecorder
	SecretDataBuilder           *helpers.SecretDataBuilder
	HMACValidator               helpers.HMACValidator
	MinRefreshAfter             time.Duration
	referenceCache              ResourceReferenceCache
	GlobalTransformationOptions *helpers.GlobalTransformationOptions
	BackOffRegistry             *BackOffRegistry
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpvaultsecretsapps/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//
// required for rollout-restart
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
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
		requeueAfter = d
	}

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOptions)
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
		Types: []string{
			helpers.HVSSecretTypeKV,
			helpers.HVSSecretTypeRotating,
		},
	}

	resp, err := fetchOpenSecretsPaginated(ctx, c, params, nil)
	if err != nil {
		logger.Error(err, "Get App Secrets", "appName", o.Spec.AppName)
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	}

	dynamicSecrets, err := getHVSDynamicSecrets(ctx, c, o.Spec.AppName)
	if err != nil {
		logger.Error(err, "Get Dynamic Secrets", "appName", o.Spec.AppName)
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	}
	// Add the dynamic secrets to the OpenAppSecrets response to be processed
	// along with the rest of the App secrets
	resp.Payload.Secrets = append(resp.Payload.Secrets, dynamicSecrets...)

	// Remove this app from the backoff registry now that we're done with HVS
	// API calls
	r.BackOffRegistry.Delete(req.NamespacedName)

	// Calculate next requeue time based on whichever comes first between the
	// current `requeueAfter` and all the dynamic secret renewal times. Also set
	// the dynamic secret statuses while looping through the dynamic secrets.
	renewPercent := getDynamicRenewPercent(o.Spec.SyncConfig)
	o.Status.DynamicSecrets = nil
	for _, secret := range dynamicSecrets {
		requeueAfter = getNextRequeue(requeueAfter, secret.DynamicInstance, renewPercent, time.Now())
		o.Status.DynamicSecrets = append(o.Status.DynamicSecrets, makeHVSDynamicStatus(secret))
	}
	if requeueAfter.Seconds() > 0 {
		requeueAfter = computeHorizonWithJitter(requeueAfter)
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

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

// getHVSDynamicSecrets returns the "open" dynamic secrets for the given HVS app
func getHVSDynamicSecrets(ctx context.Context, c hvsclient.ClientService, appName string) ([]*models.Secrets20231128OpenSecret, error) {
	logger := log.FromContext(ctx).WithName("getHVSDynamicSecrets")

	// Fetch the unopened AppSecrets to get the full list of secrets (including
	// dynamic)
	secretsListParams := &hvsclient.ListAppSecretsParams{
		Context: ctx,
		AppName: appName,
		// Type is currently non-functional, so we have to filter the list
		// ourselves
		// Type: ptr.To(helpers.HVSSecretTypeDynamic),
	}

	filter := func(secret *models.Secrets20231128Secret) bool {
		if secret == nil {
			return false
		}
		return secret.Type == helpers.HVSSecretTypeDynamic
	}

	listResp, err := listSecretsPaginated(ctx, c, secretsListParams, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list app Secrets for app %s: %w", appName, err)
	}

	var secrets []*models.Secrets20231128OpenSecret
	if listResp.Payload != nil {
		// TODO(tvoran): only fetch/create dynamic secrets that are new or are
		// due for rotation
		for _, appSecret := range listResp.Payload.Secrets {
			secretParams := &hvsclient.OpenAppSecretParams{
				Context:    ctx,
				AppName:    appName,
				SecretName: appSecret.Name,
			}
			resp, err := c.OpenAppSecret(secretParams, nil)
			if err != nil {
				if errResp := parseHVSErrorResponse(err); errResp != nil && errResp.StatusCode == http.StatusNotFound {
					logger.V(consts.LogLevelWarning).Info(
						"Dynamic secret not found, skipping",
						"appName", appName, "secretName", appSecret.Name)
					continue
				}

				return nil, fmt.Errorf("failed to get dynamic secret %s in app %s: %w",
					appSecret.Name, appName, err)
			}
			if resp != nil && resp.Payload != nil {
				secrets = append(secrets, resp.Payload.Secret)
			}
		}
	}

	return secrets, nil
}

// getDynamicRenewPercent returns the default renewal percent or the synconfig
// dynamic renewal percent in that order of precendence
func getDynamicRenewPercent(syncConfig *secretsv1beta1.HVSSyncConfig) int {
	renewPercent := defaultDynamicRenewPercent
	if syncConfig != nil && syncConfig.Dynamic != nil && syncConfig.Dynamic.RenewalPercent != 0 {
		renewPercent = syncConfig.Dynamic.RenewalPercent
	}
	return renewPercent
}

func makeHVSDynamicStatus(secret *models.Secrets20231128OpenSecret) secretsv1beta1.HVSDynamicStatus {
	status := secretsv1beta1.HVSDynamicStatus{
		Name: secret.Name,
	}
	if secret.DynamicInstance != nil {
		status.CreatedAt = secret.DynamicInstance.CreatedAt.String()
		status.ExpiresAt = secret.DynamicInstance.ExpiresAt.String()
		status.TTL = secret.DynamicInstance.TTL
	}
	return status
}

// getNextRequeue returns whichever is less between the current `requeueAfter`
// and the next renewal time of the dynamic secret instance
func getNextRequeue(requeueAfter time.Duration, dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance, renewPercent int, now time.Time) time.Duration {
	if dynamicInstance == nil {
		return requeueAfter
	}
	nextRequeue := requeueAfter

	// Calculate the time when the dynamic secret should be renewed
	fullTTL := time.Time(dynamicInstance.ExpiresAt).Sub(time.Time(dynamicInstance.CreatedAt))
	renewPoint := fullTTL * time.Duration(renewPercent) / 100
	renewTime := time.Time(dynamicInstance.CreatedAt).Add(renewPoint)
	howLongUntilRenewTime := renewTime.Sub(now)

	if howLongUntilRenewTime < requeueAfter || requeueAfter == 0 {
		nextRequeue = howLongUntilRenewTime
	}
	if nextRequeue <= 0 {
		nextRequeue = defaultDynamicRequeue
	}

	return nextRequeue
}

type (
	// openSecretFilter is a function that filters out secrets from the OpenAppSecrets API response.
	// The function should return true to keep the secret.
	openSecretFilter func(*models.Secrets20231128OpenSecret) bool
	// secretFilter is a function that filters out secrets from the ListAppSecrets API response
	// The function should return true to keep the secret.
	secretFilter func(*models.Secrets20231128Secret) bool
)

// fetchOpenSecretsPaginated fetches all pages of the OpenAppSecrets API call and returns a slice of responses.
// Note: Some attributes of the params will be modified in the process of fetching the secrets.
func fetchOpenSecretsPaginated(ctx context.Context, c hvsclient.ClientService, params *hvsclient.OpenAppSecretsParams, filter openSecretFilter) (*hvsclient.OpenAppSecretsOK, error) {
	if params == nil {
		return nil, fmt.Errorf("params is nil")
	}

	logger := log.FromContext(ctx).WithName("fetchOpenSecretsPaginated")
	logger.V(consts.LogLevelDebug).Info("Fetching OpenSecrets",
		"appName", params.AppName, "types", params.Types)

	var resp *hvsclient.OpenAppSecretsOK
	var secrets []*models.Secrets20231128OpenSecret
	var err error
	for {
		resp, err = c.OpenAppSecrets(params, nil)
		if err != nil {
			return nil, err
		}

		if resp == nil {
			return nil, fmt.Errorf("failed to open app secrets: response is nil")
		}

		for _, secret := range resp.Payload.Secrets {
			if filter != nil && !filter(secret) {
				continue
			}
			secrets = append(secrets, secret)
		}

		if resp.Payload.Pagination == nil || resp.Payload.Pagination.NextPageToken == "" {
			break
		}

		params.PaginationNextPageToken = ptr.To(resp.Payload.Pagination.NextPageToken)
	}

	if resp != nil {
		resp = &hvsclient.OpenAppSecretsOK{
			Payload: &models.Secrets20231128OpenAppSecretsResponse{
				Secrets:    secrets,
				Pagination: resp.Payload.Pagination,
			},
		}
	}

	return resp, nil
}

// listSecretsPaginated fetches all pages of the AppSecrets API call and returns a slice of responses.
// Note: Some attributes of the params will be modified in the process of fetching the secrets.
func listSecretsPaginated(ctx context.Context, c hvsclient.ClientService, params *hvsclient.ListAppSecretsParams, filter secretFilter) (*hvsclient.ListAppSecretsOK, error) {
	if params == nil {
		return nil, fmt.Errorf("params is nil")
	}

	logger := log.FromContext(ctx).WithName("listSecretsPaginated")
	logger.V(consts.LogLevelDebug).Info("Listing Secrets", "appName")

	var resp *hvsclient.ListAppSecretsOK
	var secrets []*models.Secrets20231128Secret
	var err error
	for {
		resp, err = c.ListAppSecrets(params, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to open app secrets: %w", err)
		}

		if resp != nil {
			for _, secret := range resp.Payload.Secrets {
				if filter != nil && !filter(secret) {
					continue
				}
				secrets = append(secrets, secret)
			}
		}

		if resp.Payload.Pagination == nil || resp.Payload.Pagination.NextPageToken == "" {
			break
		}

		params.PaginationNextPageToken = ptr.To(resp.Payload.Pagination.NextPageToken)
	}

	if resp != nil {
		resp = &hvsclient.ListAppSecretsOK{
			Payload: &models.Secrets20231128ListAppSecretsResponse{
				Secrets:    secrets,
				Pagination: resp.Payload.Pagination,
			},
		}
	}
	return resp, nil
}

// hvsErrorResponse contains the method, path pattern, and status code of an HVS API error
// response.
type hvsErrorResponse struct {
	Method      string
	PathPattern string
	StatusCode  int
}

// parseHVSErrorResponse parses the error message from the HVS API and returns
// the method, path pattern, and status code if the error message matches the
// expected format.
func parseHVSErrorResponse(err error) *hvsErrorResponse {
	if err == nil {
		return nil
	}

	matches := hvsErrorRe.FindStringSubmatch(err.Error())
	if len(matches) != 4 {
		return nil
	}

	code, err := strconv.Atoi(matches[3])
	if err != nil {
		// should never happen since the regex is looking for digits
		return nil
	}

	return &hvsErrorResponse{
		Method:      matches[1],
		PathPattern: matches[2],
		StatusCode:  code,
	}
}
