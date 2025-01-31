// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	httptransport "github.com/go-openapi/runtime/client"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	hcpconfig "github.com/hashicorp/hcp-sdk-go/config"
	hcpclient "github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

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

	// shadowSecretPrefix is used for naming k8s secrets that store a cached
	// copy of HVS dynamic secret responses
	shadowSecretPrefix = "vso-hvs"

	// fieldMACMessage is the field name for the MAC of the data cached in the
	// shadow secret
	fieldMACMessage = "vso-messageMAC"
)

var (
	userAgent = fmt.Sprintf("vso/%s", version.Version().String())
	// hvsErrorRe is a regexp to parse the error message from the HVS API
	// The error message is expected to be in the format:
	// [METHOD PATH_PATTERN][STATUS_CODE]
	hvsErrorRe = regexp.MustCompile(`\[(\w+) (.+)]\[(\d+)]`)

	hvsaLabelPrefix = fmt.Sprintf("%s.%s", "hcpvaultsecretsapps",
		secretsv1beta1.GroupVersion.Group)
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
	once                        sync.Once
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
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonHVSSecret,
				"Field validation failed, err=%s", err)
			return ctrl.Result{}, err
		}
		if d.Seconds() > 0 {
			requeueAfter = computeHorizonWithJitter(d)
		}
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
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonHVSClientConfigError,
			"Failed to instantiate HVS client: %s", err)
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
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonHVSSecret,
			"Failed to get HVS App secrets: %s", err)
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	}

	// Get shadowed dynamic secret data (if any)
	shadowSecrets, err := r.getShadowSecretData(ctx, o)
	if err != nil {
		// If we can't get the shadow secret data, log a warning and proceed
		// without retrying since user intervention would be required to fix it
		// and the shadow secret will just be recreated at the end of
		// Reconcile().
		logger.V(consts.LogLevelWarning).Info("Failed to get shadow secret data, proceeding without shadow cache",
			"appName", o.Spec.AppName, "err", err)
	}

	renewPercent := getDynamicRenewPercent(o.Spec.SyncConfig)
	dynamicSecrets, err := getHVSDynamicSecrets(ctx, c, o.Spec.AppName, renewPercent, shadowSecrets)
	if err != nil {
		logger.Error(err, "Get Dynamic Secrets", "appName", o.Spec.AppName)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonHVSSecret,
			"Failed to get HVS dynamic secrets: %s", err)
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	}
	// Add the dynamic secrets to the OpenAppSecrets response to be processed
	// along with the rest of the App secrets
	if len(dynamicSecrets.secrets) > 0 {
		resp.Payload.Secrets = append(resp.Payload.Secrets, dynamicSecrets.secrets...)
	}

	// Remove this app from the backoff registry now that we're done with HVS
	// API calls
	r.BackOffRegistry.Delete(req.NamespacedName)

	o.Status.DynamicSecrets = dynamicSecrets.statuses

	// Calculate next requeue time based on whichever comes first between the
	// current `requeueAfter` and the next dynamic secret renewal time.
	if dynamicSecrets.nextRenewal.timeToNextRenewal > 0 {
		_, j := computeMaxJitter(dynamicSecrets.nextRenewal.ttl)
		nextDynamicRequeue := dynamicSecrets.nextRenewal.timeToNextRenewal + time.Duration(j)

		if requeueAfter == 0 || nextDynamicRequeue < requeueAfter {
			logger.V(consts.LogLevelTrace).Info("Setting requeueAfter to the next dynamic secret renewal time",
				"appName", o.Spec.AppName, "requeueAfter", requeueAfter,
				"nextDynamicRequeue", nextDynamicRequeue)
			requeueAfter = nextDynamicRequeue
		}
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
		if err := r.storeShadowSecretData(ctx, o, dynamicSecrets.secrets); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
				"Failed to store shadow secret data for appName %s: %s",
				o.Spec.AppName, err)
			return ctrl.Result{}, nil
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

func (r *HCPVaultSecretsAppReconciler) startOrphanedShadowSecretCleanup(ctx context.Context, cleanupOrphanedShadowSecretInterval time.Duration) error {
	var err error

	r.once.Do(func() {
		for {
			select {
			case <-ctx.Done():
				if ctx.Err() != nil {
					err = ctx.Err()
				}
				return
			// runs the cleanup process once every hour or as specified by the user
			case <-time.After(cleanupOrphanedShadowSecretInterval):
				r.cleanupOrphanedShadowSecrets(ctx)
			}
		}
	})

	return err
}

func (r *HCPVaultSecretsAppReconciler) cleanupOrphanedShadowSecrets(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("cleanupOrphanedShadowSecrets")
	var errs error

	namespaceLabelKey := hvsaLabelPrefix + "/namespace"
	nameLabelKey := hvsaLabelPrefix + "/name"

	// filtering only for dynamic secrets, also checking if namespace and name labels are present
	secrets := corev1.SecretList{}
	if err := r.List(ctx, &secrets, client.InNamespace(common.OperatorNamespace),
		client.MatchingLabels{"app.kubernetes.io/component": "hvs-dynamic-secret-cache"},
		client.HasLabels{namespaceLabelKey, nameLabelKey}); err != nil {
		errs = errors.Join(errs, fmt.Errorf("failed to list shadow secrets: %w", err))
	}

	for _, secret := range secrets.Items {
		namespace := secret.Labels[namespaceLabelKey]
		name := secret.Labels[nameLabelKey]
		objKey := types.NamespacedName{Namespace: namespace, Name: name}

		o := &secretsv1beta1.HCPVaultSecretsApp{}

		// get the HCPVaultSecretsApp instance that the shadow secret belongs to (if applicable)
		// no errors are returned in the loop because this could block the deletion of other
		// orphaned shadow secrets that are further along in the list
		err := r.Get(ctx, objKey, o)
		if err != nil && !apierrors.IsNotFound(err) {
			errs = errors.Join(errs, fmt.Errorf("failed to get HCPVaultSecretsApp: %w", err))
			continue
		}

		// if the HCPVaultSecretsApp has been deleted, and the shadow secret belongs to it, delete both
		if o.GetDeletionTimestamp() != nil && o.GetUID() == types.UID(secret.Labels[helpers.LabelOwnerRefUID]) {
			if err := r.handleDeletion(ctx, o); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to handle deletion of HCPVaultSecretsApp %s: %w", o.Spec.AppName, err))
			}

			logger.Info("Deleted orphaned resources associated with HCPVaultSecretsApp", "app", o.Name)
		} else if apierrors.IsNotFound(err) || secret.GetDeletionTimestamp() != nil {
			// otherwise, delete the single shadow secret if it has a deletion timestamp
			if err := helpers.DeleteSecret(ctx, r.Client, objKey); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to delete shadow secret %s: %w", secret.Name, err))
			}

			logger.Info("Deleted orphaned shadow secret", "secret", secret.Name)
		}
	}

	logger.Error(errs, "Failed during cleanup of orphaned shadow secrets")
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
func (r *HCPVaultSecretsAppReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options, cleanupOrphanedShadowSecretInterval time.Duration) error {
	r.referenceCache = newResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}

	mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		err := r.startOrphanedShadowSecretCleanup(ctx, cleanupOrphanedShadowSecretInterval)
		return err
	}))

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.HCPVaultSecretsApp{}).
		WithEventFilter(syncableSecretPredicate(nil)).
		WithOptions(opts).
		Watches(
			&secretsv1beta1.SecretTransformation{},
			NewEnqueueRefRequestsHandlerST(r.referenceCache, nil),
		).
		// In order to reduce the operator's memory usage, we only watch for the
		// Secret's metadata. That is sufficient for us to know when a Secret is
		// deleted. If we ever need to access to the Secret's data, we can always fetch
		// it from the API server in a RequestHandler, selectively based on the Secret's
		// labels.
		WatchesMetadata(
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

func (r *HCPVaultSecretsAppReconciler) handleDeletion(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp) error {
	logger := log.FromContext(ctx)
	objKey := client.ObjectKeyFromObject(o)
	r.referenceCache.Remove(SecretTransformation, objKey)
	r.BackOffRegistry.Delete(objKey)
	shadowObjKey := makeShadowObjKey(o)
	if err := helpers.DeleteSecret(ctx, r.Client, shadowObjKey); err != nil {
		logger.Error(err, "Failed to delete shadow secret", "shadow secret", shadowObjKey)
	}
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

// getShadowSecretData retrieves shadowed secret data from a k8s secret
func (r *HCPVaultSecretsAppReconciler) getShadowSecretData(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp) (map[string]*models.Secrets20231128OpenSecret, error) {
	// Get the shadow secret for the HCPVaultSecretsApp
	shadowObjKey := makeShadowObjKey(o)
	shadowSecret, err := helpers.GetSecret(ctx, r.Client, shadowObjKey)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get shadow secret %s/%s: %w",
			shadowObjKey.Namespace, shadowObjKey.Name, err)
	}
	// Verify the hmac of the data in the shadow secret
	lastHMAC := shadowSecret.Data[fieldMACMessage]
	delete(shadowSecret.Data, fieldMACMessage)
	dataBytes, err := json.Marshal(shadowSecret.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal shadow secret data %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	valid, _, err := r.HMACValidator.Validate(ctx, r.Client, dataBytes, lastHMAC)
	if err != nil {
		return nil, fmt.Errorf("failed to validate HMAC of HVS shadow secret data for %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	if !valid {
		return nil, fmt.Errorf("HVS shadow secret %s for %s/%s has been tampered with",
			shadowObjKey.String(), o.Namespace, o.Name)
	}
	// Check labels match
	expectedLabels, err := makeShadowLabels(o)
	if err != nil {
		return nil, fmt.Errorf("failed to make shadow secret labels for %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	if !helpers.MatchingLabels(expectedLabels, shadowSecret.Labels) {
		return nil, fmt.Errorf("shadow secret labels %v did not match expected labels %v for %s/%s",
			shadowSecret.Labels, expectedLabels,
			shadowObjKey.Namespace, shadowObjKey.Name)
	}
	// Decode shadowSecret.Data into a map of OpenSecret's
	if shadowSecret != nil {
		openSecrets := make(map[string]*models.Secrets20231128OpenSecret)
		for k, v := range shadowSecret.Data {
			secret, err := helpers.FromHVSShadowSecret(v)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal shadow secret data %s/%s: %w",
					shadowObjKey.Namespace, shadowObjKey.Name, err)
			}
			openSecrets[k] = secret
		}
		return openSecrets, nil
	}

	return nil, nil
}

func (r *HCPVaultSecretsAppReconciler) storeShadowSecretData(ctx context.Context, o *secretsv1beta1.HCPVaultSecretsApp, secrets []*models.Secrets20231128OpenSecret) error {
	shadowObjKey := makeShadowObjKey(o)

	// Delete the shadow secret if there are no secrets to store
	if len(secrets) == 0 {
		return helpers.DeleteSecret(ctx, r.Client, shadowObjKey)
	}

	labels, err := makeShadowLabels(o)
	if err != nil {
		return fmt.Errorf("failed to make shadow secret labels for %s/%s: %w",
			o.Namespace, o.Name, err)
	}

	shadowSecret := &corev1.Secret{
		Immutable: ptr.To(true),
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowObjKey.Name,
			Namespace: shadowObjKey.Namespace,
			Labels:    labels,
		},
	}

	shadowSecretData, err := helpers.MakeHVSShadowSecretData(secrets)
	if err != nil {
		return fmt.Errorf("failed to marshal shadow secret data %s/%s: %w",
			shadowObjKey.Namespace, shadowObjKey.Name, err)
	}
	shadowSecret.Data = shadowSecretData

	// HMAC the shadowSecretData, store along with the secrets
	b, err := json.Marshal(shadowSecretData)
	if err != nil {
		return fmt.Errorf("failed to marshal shadow secret data %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	h, err := r.HMACValidator.HMAC(ctx, r.Client, b)
	if err != nil {
		return fmt.Errorf("failed to HMAC shadow secret data %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	shadowSecret.Data[fieldMACMessage] = h

	if err := helpers.StoreImmutableSecret(ctx, r.Client, shadowSecret); err != nil {
		return fmt.Errorf("failed to create or update shadow secret %s/%s: %w",
			shadowObjKey.Namespace, shadowObjKey.Name, err)
	}

	return nil
}

func makeShadowLabels(o *secretsv1beta1.HCPVaultSecretsApp) (map[string]string, error) {
	labels, err := helpers.OwnerLabelsForObj(o)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner labels for %s/%s: %w",
			o.Namespace, o.Name, err)
	}
	labels["app.kubernetes.io/component"] = "hvs-dynamic-secret-cache"
	labels[hvsaLabelPrefix+"/hvs-app-name"] = o.Spec.AppName
	labels[hvsaLabelPrefix+"/name"] = o.Name
	labels[hvsaLabelPrefix+"/namespace"] = o.Namespace

	return labels, nil
}

type nextRenewalDetails struct {
	// How long until the next renewal (StartTime + renewPercent of TTL - now)
	timeToNextRenewal time.Duration
	// Full ttl of the secret
	ttl time.Duration
}

type hvsDynamicSecretResult struct {
	secrets     []*models.Secrets20231128OpenSecret
	nextRenewal nextRenewalDetails
	statuses    []secretsv1beta1.HVSDynamicStatus
}

// getHVSDynamicSecrets returns the "open" dynamic secrets for the given HVS
// app, a slice of HCPVaultSecretsApp statuses, and the details of the next
// renewal
func getHVSDynamicSecrets(ctx context.Context, c hvsclient.ClientService, appName string, renewPercent int, shadowSecrets map[string]*models.Secrets20231128OpenSecret) (*hvsDynamicSecretResult, error) {
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

	var statuses []secretsv1beta1.HVSDynamicStatus
	var nextRenewal nextRenewalDetails
	var secrets []*models.Secrets20231128OpenSecret
	if listResp.Payload != nil {
		for _, appSecret := range listResp.Payload.Secrets {
			// If the secret is in the shadow secrets, check if it should be
			// renewed, otherwise append and skip to the next one
			if s, exists := shadowSecrets[appSecret.Name]; exists {
				renew := false
				if timeForRenewal(s.DynamicInstance, renewPercent, time.Now()) {
					logger.V(consts.LogLevelTrace).Info("Dynamic secret is due for renewal",
						"appName", appName, "secretName", appSecret.Name,
						"expiresAt", s.DynamicInstance.ExpiresAt, "renewPercent", renewPercent,
						"ttl", s.DynamicInstance.TTL)
					renew = true
				} else if s.LatestVersion != appSecret.LatestVersion {
					logger.V(consts.LogLevelTrace).Info("Dynamic secret latest version has changed",
						"appName", appName, "secretName", appSecret.Name,
						"latestVersion", appSecret.LatestVersion,
						"oldLatestVersion", s.LatestVersion)
					renew = true
				} else if s.CreatedAt.String() != appSecret.CreatedAt.String() {
					logger.V(consts.LogLevelTrace).Info("Dynamic secret created at has changed",
						"appName", appName, "secretName", appSecret.Name,
						"createdAt", appSecret.CreatedAt, "oldCreatedAt", s.CreatedAt)
					renew = true
				}
				if !renew {
					// At this point we know we've seen this secret previously,
					// it's not time to renew it, the version of the secret
					// hasn't changed, and it hasn't been deleted/recreated with
					// the same name, so it's safe to add the shadowed secret to
					// the return list and skip renewal.
					logger.V(consts.LogLevelTrace).Info("Skipping dynamic secret renewal",
						"appName", appName, "secretName", appSecret.Name,
						"expires_at", s.DynamicInstance.ExpiresAt)
					secrets = append(secrets, s)
					nextRenewal = getTimeToNextRenewal(nextRenewal, s.DynamicInstance,
						renewPercent, time.Now())
					statuses = append(statuses, makeHVSDynamicStatus(s))
					continue
				}
			}
			// Proceed with fetching the dynamic secret from HVS (which
			// generates a new set of credentials)
			secretParams := &hvsclient.OpenAppSecretParams{
				Context:    ctx,
				AppName:    appName,
				SecretName: appSecret.Name,
			}
			resp, err := c.OpenAppSecret(secretParams, nil)
			if err != nil {
				if errResp := parseHVSResponseError(err); errResp != nil && errResp.StatusCode == http.StatusNotFound {
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
				nextRenewal = getTimeToNextRenewal(nextRenewal,
					resp.Payload.Secret.DynamicInstance, renewPercent, time.Now())
				statuses = append(statuses, makeHVSDynamicStatus(resp.Payload.Secret))
			}
		}
	}

	return &hvsDynamicSecretResult{
		secrets:     secrets,
		nextRenewal: nextRenewal,
		statuses:    statuses,
	}, nil
}

// timeForRenewal returns true if the dynamic secret should be renewed now
func timeForRenewal(dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance, renewPercent int, now time.Time) bool {
	if dynamicInstance == nil {
		return true
	}
	renewTime := getRenewTime(dynamicInstance, renewPercent)
	return now.After(renewTime)
}

// getRenewTime returns the instant in time when the dynamic secret can be renewed
func getRenewTime(dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance, renewPercent int) time.Time {
	if dynamicInstance == nil {
		return time.Time{}
	}
	fullTTL := time.Time(dynamicInstance.ExpiresAt).Sub(time.Time(dynamicInstance.CreatedAt))
	renewPoint := fullTTL * time.Duration(renewPercent) / 100
	return time.Time(dynamicInstance.CreatedAt).Add(renewPoint)
}

// getTimeToNextRenewal returns the time until the next renewal of the dynamic secret
func getTimeToNextRenewal(currentRenewal nextRenewalDetails, dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance, renewPercent int, now time.Time) nextRenewalDetails {
	if dynamicInstance == nil {
		return currentRenewal
	}
	renewTime := getRenewTime(dynamicInstance, renewPercent)
	timeToNextRenewal := renewTime.Sub(now)
	if timeToNextRenewal < 0 {
		timeToNextRenewal = defaultDynamicRequeue
	}
	if timeToNextRenewal < currentRenewal.timeToNextRenewal || currentRenewal.timeToNextRenewal == 0 {
		return nextRenewalDetails{
			timeToNextRenewal: timeToNextRenewal,
			ttl:               time.Time(dynamicInstance.ExpiresAt).Sub(time.Time(dynamicInstance.CreatedAt)),
		}
	}
	return currentRenewal
}

// HVS shadow secrets live in the operator namespace and are named with a hash
// of the HCPVaultSecretsApp's namespace and name
func makeShadowObjKey(o client.Object) client.ObjectKey {
	input := fmt.Sprintf("%s-%s", o.GetNamespace(), o.GetName())
	name := strings.ToLower(
		fmt.Sprintf("%s-%s", shadowSecretPrefix, helpers.HashString(input)))
	return client.ObjectKey{
		Namespace: common.OperatorNamespace,
		Name:      name,
	}
}

// getDynamicRenewPercent returns the HVSSyncConfig dynamic renewal percent or
// the default renewal percent in that order of precendence
func getDynamicRenewPercent(syncConfig *secretsv1beta1.HVSSyncConfig) int {
	renewPercent := defaultDynamicRenewPercent
	if syncConfig != nil && syncConfig.Dynamic != nil && syncConfig.Dynamic.RenewalPercent != 0 {
		renewPercent = syncConfig.Dynamic.RenewalPercent
	}
	return capRenewalPercent(renewPercent)
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

	return &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20231128OpenAppSecretsResponse{
			Secrets:    secrets,
			Pagination: resp.Payload.Pagination,
		},
	}, nil
}

// listSecretsPaginated fetches all pages of the AppSecrets API call and returns a slice of responses.
// Note: Some attributes of the params will be modified in the process of fetching the secrets.
func listSecretsPaginated(ctx context.Context, c hvsclient.ClientService, params *hvsclient.ListAppSecretsParams, filter secretFilter) (*hvsclient.ListAppSecretsOK, error) {
	if params == nil {
		return nil, fmt.Errorf("params is nil")
	}

	logger := log.FromContext(ctx).WithName("listSecretsPaginated")
	logger.V(consts.LogLevelDebug).Info("Listing Secrets", "appName", params.AppName)

	var resp *hvsclient.ListAppSecretsOK
	var secrets []*models.Secrets20231128Secret
	var err error
	for {
		resp, err = c.ListAppSecrets(params, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to open app secrets: %w", err)
		}

		if resp == nil {
			return nil, fmt.Errorf("failed to list app secrets: response is nil")
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

	return &hvsclient.ListAppSecretsOK{
		Payload: &models.Secrets20231128ListAppSecretsResponse{
			Secrets:    secrets,
			Pagination: resp.Payload.Pagination,
		},
	}, nil
}

// hvsResponseErrorStatus contains the method, path pattern, and status code of an HVS API error
// response.
type hvsResponseErrorStatus struct {
	Method      string
	PathPattern string
	StatusCode  int
}

// parseHVSResponseError parses the error message from the HVS API and returns
// the method, path pattern, and status code if the error message matches the
// expected format.
func parseHVSResponseError(err error) *hvsResponseErrorStatus {
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

	return &hvsResponseErrorStatus{
		Method:      matches[1],
		PathPattern: matches[2],
		StatusCode:  code,
	}
}
