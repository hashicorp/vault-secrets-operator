// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"

	"github.com/hashicorp/vault-secrets-operator/vault"
)

const (
	vaultDynamicSecretFinalizer = "vaultdynamicsecret.secrets.hashicorp.com/finalizer"
)

// staticCredsJitterHorizon should be used when computing the jitter
// duration for the static-creds rotation time horizon.
var (
	staticCredsJitterHorizon = time.Second * 3
	vdsJitterFactor          = 0.05
)

var _ reconcile.Reconciler = &VaultDynamicSecretReconciler{}

// VaultDynamicSecretReconciler reconciles a VaultDynamicSecret object
type VaultDynamicSecretReconciler struct {
	client.Client
	Scheme                      *runtime.Scheme
	Recorder                    record.EventRecorder
	ClientFactory               vault.ClientFactory
	HMACValidator               helpers.HMACValidator
	SyncRegistry                *SyncRegistry
	BackOffRegistry             *BackOffRegistry
	referenceCache              ResourceReferenceCache
	GlobalTransformationOptions *helpers.GlobalTransformationOptions
	// sourceCh is used to trigger a requeue of resource instances from an
	// external source. Should be set on a source.Channel in SetupWithManager.
	// This channel should be closed when the controller is stopped.
	SourceCh chan event.GenericEvent
	// runtimePodUID should always be set when updating resource's Status.
	// This is done via the downwardAPI. We get the current Pod's UID from either the
	// OPERATOR_POD_UID environment variable, or the /var/run/podinfo/uid file; in that order.
	runtimePodUID types.UID
	SecretsClient client.Client
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//
// required for rollout-restart
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
//
// needed for managing cached Clients, duplicated in vaultconnection_controller.go
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch

// Reconcile ensures that the VaultDynamicSecret Custom Resource is synced from Vault to its
// configured Kubernetes secret. The resource will periodically be reconciled to renew the
// dynamic secrets lease in Vault. If the renewal fails for any reason then the secret
// will be re-synced from Vault aka. rotated. If a secret rotation occurs and the resource has
// RolloutRestartTargets configured, then a request to "rollout restart"
// the configured Deployment, StatefulSet, ReplicaSet will be made to Kubernetes.
func (r *VaultDynamicSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.runtimePodUID == "" {
		if val := os.Getenv("OPERATOR_POD_UID"); val != "" {
			r.runtimePodUID = types.UID(val)
		}
	}
	if r.runtimePodUID == "" {
		if b, err := os.ReadFile("/var/run/podinfo/uid"); err == nil {
			r.runtimePodUID = types.UID(b)
		}
	}

	logger := log.FromContext(ctx).WithValues("podUID", r.runtimePodUID)
	o := &secretsv1beta1.VaultDynamicSecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "error getting resource from k8s", "obj", o)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		return ctrl.Result{}, r.handleDeletion(ctx, o)
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

	destExists, _ := helpers.CheckSecretExists(ctx, r.Client, o)
	if !o.Spec.Destination.Create && !destExists {
		logger.Info("Destination secret does not exist, either create it or "+
			"set .spec.destination.create=true", "destination", o.Spec.Destination)
		return ctrl.Result{RequeueAfter: requeueDurationOnError}, nil
	}

	vClient, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault client: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	// we can ignore the error here, since it was handled above in the Get() call.
	clientCacheKey, _ := vClient.GetCacheKey()
	lastClientCacheKey := o.Status.VaultClientMeta.CacheKey
	lastClientID := o.Status.VaultClientMeta.ID

	// update the VaultClientMeta in the resource's status.
	o.Status.VaultClientMeta.CacheKey = clientCacheKey.String()
	o.Status.VaultClientMeta.ID = vClient.ID()

	var syncReason string
	// doSync indicates that the controller should perform the secret sync,
	switch {
	// indicates that the resource has not been synced yet.
	case o.Status.LastGeneration == 0:
		syncReason = consts.ReasonInitialSync
	// indicates that the resource has been added to the SyncRegistry
	// and must be synced.
	case r.SyncRegistry.Has(req.NamespacedName):
		// indicates that the resource has been added to the SyncRegistry
		// and must be synced.
		syncReason = consts.ReasonForceSync
	// indicates that the resource has been updated since the last sync.
	case o.GetGeneration() != o.Status.LastGeneration:
		syncReason = consts.ReasonResourceUpdated
	// indicates that the destination secret does not exist and the resource is configured to create it.
	case o.Spec.Destination.Create && !destExists:
		syncReason = consts.ReasonInexistentDestination
	// indicates that the cache key has changed since the last sync. This can happen
	// when the VaultAuth or VaultConnection objects are updated since the last sync.
	case lastClientCacheKey != "" && lastClientCacheKey != o.Status.VaultClientMeta.CacheKey:
		syncReason = consts.ReasonVaultClientConfigChanged
	// indicates that the Vault client ID has changed since the last sync. This can
	// happen when the client has re-authenticated to Vault since the last sync.
	case lastClientID != "" && lastClientID != o.Status.VaultClientMeta.ID:
		syncReason = consts.ReasonVaultTokenRotated
	}

	doSync := syncReason != ""
	leaseID := o.Status.SecretLease.ID
	if !doSync && r.runtimePodUID != "" && r.runtimePodUID != o.Status.LastRuntimePodUID {
		// don't take part in the thundering herd on start up,
		// and the lease is still within the renewal window.
		horizon, inWindow := computeRelativeHorizonWithJitter(o, time.Second*1)
		logger.Info("Restart check",
			"inWindow", inWindow,
			"horizon", horizon,
			"allowStaticCreds", o.Spec.AllowStaticCreds)
		if !o.Spec.AllowStaticCreds {
			if !inWindow {
				// means that we are not in the lease renewal window.
				r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
					"Not in renewal window after transitioning to a new leader/pod, lease_id=%s, horizon=%s",
					leaseID, horizon)
				if err := r.updateStatus(ctx, o); err != nil {
					return ctrl.Result{}, err
				}
				return ctrl.Result{RequeueAfter: horizon}, nil
			}
		} else if inWindow {
			// TODO: decouple the static-creds in-window/horizon computation from lease
			// renewal. means that we are in the rotation period.
			r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
				"In rotation period after transitioning to a new leader/pod, lease_id=%s, horizon=%s",
				leaseID, horizon)
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: horizon}, nil
		}
	}

	if !doSync && r.isRenewableLease(&o.Status.SecretLease, o, true) && !o.Spec.AllowStaticCreds && leaseID != "" {
		// Renew the lease and return from Reconcile if the lease is successfully renewed.
		if secretLease, err := r.renewLease(ctx, vClient, o); err == nil {
			if !r.isRenewableLease(secretLease, o, false) {
				return ctrl.Result{}, nil
			}

			if secretLease.ID != leaseID {
				// the new lease ID does not match, this should never happen.
				err := fmt.Errorf("lease ID changed after renewal, expected=%s, actual=%s", leaseID, secretLease.ID)
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewal, err.Error())
				return ctrl.Result{}, err
			}

			o.Status.StaticCredsMetaData = secretsv1beta1.VaultStaticCredsMetaData{}
			o.Status.SecretLease = *secretLease
			o.Status.LastRenewalTime = nowFunc().Unix()
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}

			leaseDuration := time.Duration(secretLease.LeaseDuration) * time.Second
			if leaseDuration < 1 {
				// set an artificial leaseDuration in the case the lease duration is not
				// compatible with computeHorizonWithJitter()
				leaseDuration = time.Second * 5
			}
			horizon := computeDynamicHorizonWithJitter(leaseDuration, o.Spec.RenewalPercent)
			r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
				"Renewed lease, lease_id=%s, horizon=%s", leaseID, horizon)
			return ctrl.Result{RequeueAfter: horizon}, nil
		} else {
			var e *LeaseTruncatedError
			if errors.As(err, &e) {
				r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
					"Lease renewal duration was truncated from %ds to %ds, "+
						"requesting new credentials", e.Expected, e.Actual)
			} else if !vault.IsLeaseNotFoundError(err) {
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewalError,
					"Could not renew lease, lease_id=%s, err=%s", leaseID, err)
			} else if vault.IsForbiddenError(err) {
				logger.V(consts.LogLevelWarning).Info("Tainting client", "err", err)
				vClient.Taint()
			}
			syncReason = consts.ReasonSecretLeaseRenewalError
		}
	}

	reason := consts.ReasonSecretSynced
	if o.Status.LastGeneration > 0 {
		reason = consts.ReasonSecretRotated
	}

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOptions)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	// sync the secret
	secretLease, staticCredsUpdated, err := r.syncSecret(ctx, vClient, o, transOption)
	if err != nil {
		r.SyncRegistry.Add(req.NamespacedName)
		if vault.IsForbiddenError(err) {
			logger.V(consts.LogLevelWarning).Info("Tainting client", "err", err)
			vClient.Taint()
		}
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		horizon := entry.NextBackOff()
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
			"Failed to sync the secret, horizon=%s, err=%s", horizon, err)
		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	doRolloutRestart := (doSync && o.Status.LastGeneration > 1) || staticCredsUpdated
	o.Status.SecretLease = *secretLease
	o.Status.LastRenewalTime = nowFunc().Unix()
	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	horizon := r.computePostSyncHorizon(ctx, o)
	r.Recorder.Eventf(o, corev1.EventTypeNormal, reason,
		"Secret synced, lease_id=%q, horizon=%s, sync_reason=%q",
		secretLease.ID, horizon, syncReason)

	if doRolloutRestart {
		// rollout-restart errors are not retryable
		// all error reporting is handled by helpers.HandleRolloutRestarts
		_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
	}

	if ok := r.SyncRegistry.Delete(req.NamespacedName); ok {
		logger.V(consts.LogLevelDebug).Info("Deleted object from SyncRegistry",
			"obj", req.NamespacedName)
	}

	if horizon.Seconds() == 0 {
		// no need to requeue
		logger.Info("Vault secret does not support periodic renewal/refresh via reconciliation",
			"requeue", false, "horizon", horizon)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{RequeueAfter: horizon}, nil
}

func (r *VaultDynamicSecretReconciler) isRenewableLease(secretLease *secretsv1beta1.VaultSecretLease, o *secretsv1beta1.VaultDynamicSecret, skipEventRecording bool) bool {
	renewable := secretLease.Renewable
	if !renewable && !skipEventRecording && !o.Spec.AllowStaticCreds {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewal,
			"Lease is not renewable, staticCreds=%t, info=%#v",
			o.Spec.AllowStaticCreds, secretLease)
	}

	return renewable
}

func (r *VaultDynamicSecretReconciler) isStaticCreds(meta *secretsv1beta1.VaultStaticCredsMetaData) bool {
	// the ldap and database engines have minimum rotation period of 5s, requiring a
	// minimum of 1s should be okay here.
	return meta.LastVaultRotation > 0 && (meta.RotationPeriod >= 1 || meta.RotationSchedule != "")
}

// doVault performs a Vault request based on the VaultDynamicSecret's spec.
func (r *VaultDynamicSecretReconciler) doVault(ctx context.Context, c vault.ClientBase, o *secretsv1beta1.VaultDynamicSecret) (vault.Response, error) {
	path := vault.JoinPath(o.Spec.Mount, o.Spec.Path)
	var err error
	var resp vault.Response
	var params map[string]any
	paramsLen := len(o.Spec.Params)
	if paramsLen > 0 {
		params = make(map[string]any, paramsLen)
		for k, v := range o.Spec.Params {
			params[k] = v
		}
	}

	method := o.Spec.RequestHTTPMethod
	logger := log.FromContext(ctx).WithName("doVault")
	if params != nil {
		if !(method == http.MethodPost || method == http.MethodPut) {
			logger.V(consts.LogLevelWarning).Info(
				"Params provided, ignoring specified method",
				"requestHTTPMethod", o.Spec.RequestHTTPMethod)
		}
		method = http.MethodPut
	}
	if method == "" {
		method = http.MethodGet
	}

	logger = logger.WithValues("path", path, "method", method)
	switch method {
	case http.MethodPut, http.MethodPost:
		resp, err = c.Write(ctx, vault.NewWriteRequest(path, params))
	case http.MethodGet:
		resp, err = c.Read(ctx, vault.NewReadRequest(path, nil))
	default:
		return nil, fmt.Errorf("unsupported HTTP method %q for sync", method)
	}

	if err != nil {
		logger.Error(err, "Vault request failed")
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("nil response from vault for path %s", path)
	}

	return resp, nil
}

func (r *VaultDynamicSecretReconciler) syncSecret(ctx context.Context, c vault.ClientBase,
	o *secretsv1beta1.VaultDynamicSecret, opt *helpers.SecretTransformationOption,
) (*secretsv1beta1.VaultSecretLease, bool, error) {
	logger := log.FromContext(ctx).WithName("syncSecret")

	// check if lease already exists
	if o.Status.SecretLease.ID != "" {
		logger.V(consts.LogLevelDebug).Info("Lease already exists", "leaseID", o.Status.SecretLease.ID)
		// if the lease is renewable, renew it
		if o.Status.SecretLease.Renewable {
			secretLease, err := r.renewLease(ctx, c, o)
			if err != nil {
				logger.Error(err, "Failed to renew lease")
				return nil, false, err
			}
			o.Status.SecretLease = *secretLease
			return secretLease, false, nil
		} else {
			return &o.Status.SecretLease, false, nil
		}
	}

	resp, err := r.doVault(ctx, c, o)
	if err != nil {
		return nil, false, err
	}

	if resp == nil {
		return nil, false, errors.New("nil response")
	}

	var data map[string][]byte
	secretLease := r.getVaultSecretLease(resp.Secret())
	if !r.isRenewableLease(secretLease, o, true) && o.Spec.AllowStaticCreds {
		staticCredsMeta, rotatedResponse, err := r.awaitVaultSecretRotation(ctx, o, c, resp)
		if err != nil {
			return nil, false, err
		}

		resp = rotatedResponse
		data, err = resp.SecretK8sData(opt)
		if err != nil {
			return nil, false, err
		}

		dataToMAC := maps.Clone(data)
		for _, k := range []string{"ttl", "rotation_schedule", "rotation_period", "last_vault_rotation", "_raw"} {
			delete(dataToMAC, k)
		}

		macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.SecretsClient, r.HMACValidator, o, dataToMAC)
		if err != nil {
			return nil, false, err
		}

		logger.V(consts.LogLevelTrace).Info("Secret HMAC", "macsEqual", macsEqual)

		o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)
		if macsEqual {
			return secretLease, false, nil
		}

		o.Status.StaticCredsMetaData = *staticCredsMeta
		logger.V(consts.LogLevelDebug).Info("Static creds", "status", o.Status)
	} else {
		data, err = resp.SecretK8sData(opt)
		if err != nil {
			return nil, false, err
		}
	}

	if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
		logger.Error(err, "Destination sync failed")
		return nil, false, err
	}

	return secretLease, true, nil
}

// awaitVaultSecretRotation waits for the Vault secret to be rotated. This is
// necessary for the case where the Vault secret is a static-creds secret and includes
// a rotation schedule.
func (r *VaultDynamicSecretReconciler) awaitVaultSecretRotation(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret,
	c vault.ClientBase, lastResponse vault.Response) (*secretsv1beta1.VaultStaticCredsMetaData,
	vault.Response,
	error,
) {
	logger := log.FromContext(ctx).WithName("awaitVaultSecretRotation")

	resp := lastResponse
	respData := lastResponse.Data()
	staticCredsMeta, err := vaultStaticCredsMetaDataFromData(respData)
	if err != nil {
		return nil, nil, err
	}

	// if we are not handling static creds or the rotation schedule is not set, then
	// we can return early.
	if !r.isStaticCreds(staticCredsMeta) || staticCredsMeta.RotationSchedule == "" {
		return staticCredsMeta, resp, nil
	}

	lastSyncStaticCredsMeta := o.Status.StaticCredsMetaData.DeepCopy()
	inLastSyncRotation := lastSyncStaticCredsMeta.LastVaultRotation == staticCredsMeta.LastVaultRotation
	switch {
	case !inLastSyncRotation:
		// return early, not in the last rotation
		return staticCredsMeta, resp, nil
	case lastSyncStaticCredsMeta.RotationSchedule == "":
		// return early, rotation schedule was not set in the last sync
		return staticCredsMeta, resp, nil
	case lastSyncStaticCredsMeta.RotationSchedule != staticCredsMeta.RotationSchedule:
		// return early, rotation schedule has changed
		return staticCredsMeta, resp, nil
	}

	logger = logger.WithValues(
		"staticCredsMeta", staticCredsMeta,
		"lastSyncStaticCredsMeta", lastSyncStaticCredsMeta,
		"ttl", staticCredsMeta.TTL,
		"inLastSyncRotation", inLastSyncRotation,
	)

	bo := backoff.NewExponentialBackOff(
		// the minimum rotation period is 5s, so it should be safe to double that.
		// Ideally we could use the rotation's TTL value here, but that value is not
		// considered to be reliable to the TTL roll-over bug that might exist in the database
		// secrets engine.
		backoff.WithMaxElapsedTime(time.Second*10),
		backoff.WithMaxInterval(time.Second*2))
	if err := backoff.Retry(
		func() error {
			resp, err = r.doVault(ctx, c, o)
			if err != nil {
				return err
			}

			newStaticCredsMeta, err := vaultStaticCredsMetaDataFromData(resp.Data())
			if err != nil {
				return err
			}

			var retryError error
			if newStaticCredsMeta.LastVaultRotation == staticCredsMeta.LastVaultRotation {
				// in the case where we are in the rotation period, we need to wait for the next
				// rotation if it is less than 2s away or if the ttl has increased wrt. to the
				// last rotation. An increase in ttl indicates that secrets engine has the TTL
				// rollover bug, so we need to wait for the next rotation in order to get the
				// correct/true TTL value.
				if newStaticCredsMeta.TTL <= 2 {
					retryError = errors.New("near rotation, ttl<=2")
				} else if newStaticCredsMeta.TTL >= lastSyncStaticCredsMeta.TTL {
					retryError = errors.New("not rotated, handling ttl rollover bug")
				}
			}

			logger.V(consts.LogLevelDebug).Info("Stale static creds backoff",
				"newStaticCredsMeta", newStaticCredsMeta,
				"retryError", retryError,
			)
			if retryError != nil {
				return retryError
			}

			staticCredsMeta = newStaticCredsMeta
			return nil
		}, bo); err != nil {
		return nil, nil, err
	}

	return staticCredsMeta, resp, nil
}

func (r *VaultDynamicSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) error {
	if r.runtimePodUID != "" {
		o.Status.LastRuntimePodUID = r.runtimePodUID
	}

	o.Status.LastGeneration = o.GetGeneration()
	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultDynamicSecretFinalizer)
	return err
}

func (r *VaultDynamicSecretReconciler) getVaultSecretLease(resp *api.Secret) *secretsv1beta1.VaultSecretLease {
	return &secretsv1beta1.VaultSecretLease{
		ID:            resp.LeaseID,
		LeaseDuration: resp.LeaseDuration,
		Renewable:     resp.Renewable,
		RequestID:     resp.RequestID,
	}
}

func (r *VaultDynamicSecretReconciler) renewLease(
	ctx context.Context, c vault.ClientBase, o *secretsv1beta1.VaultDynamicSecret,
) (*secretsv1beta1.VaultSecretLease, error) {
	resp, err := c.Write(ctx, vault.NewWriteRequest("/sys/leases/renew", map[string]any{
		"lease_id":  o.Status.SecretLease.ID,
		"increment": o.Status.SecretLease.LeaseDuration,
	}))
	if err != nil {
		return nil, err
	}
	// The renewal duration can come back as less than the requested increment
	// if the time remaining on max_ttl is less than the increment. In this case
	// return an error so new credentials are acquired.
	if resp.Secret().LeaseDuration < o.Status.SecretLease.LeaseDuration {
		return r.getVaultSecretLease(resp.Secret()), &LeaseTruncatedError{
			Expected: o.Status.SecretLease.LeaseDuration,
			Actual:   resp.Secret().LeaseDuration,
		}
	}

	return r.getVaultSecretLease(resp.Secret()), nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultDynamicSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = newResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}

	r.ClientFactory.RegisterClientCallbackHandler(
		vault.ClientCallbackHandler{
			On:       vault.ClientCallbackOnLifetimeWatcherDone | vault.ClientCallbackOnCacheRemoval,
			Callback: r.vaultClientCallback,
		},
	)

	// TODO: close this channel when the controller is stopped.
	r.SourceCh = make(chan event.GenericEvent)
	m := ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultDynamicSecret{}).
		WithOptions(opts).
		WithEventFilter(syncableSecretPredicate(r.SyncRegistry)).
		Watches(
			&secretsv1beta1.SecretTransformation{},
			NewEnqueueRefRequestsHandlerST(r.referenceCache, r.SyncRegistry),
		).
		// In order to reduce the operator's memory usage, we only watch for the
		// Secret's metadata. That is sufficient for us to know when a Secret is
		// deleted. If we ever need to access to the Secret's data, we can always fetch
		// it from the API server in a RequestHandler, selectively based on the Secret's
		// labels.
		WatchesMetadata(
			&corev1.Secret{},
			&enqueueOnDeletionRequestHandler{
				gvk: secretsv1beta1.GroupVersion.WithKind(VaultDynamicSecret.String()),
			},
			builder.WithPredicates(&secretsPredicate{}),
		).
		WatchesRawSource(
			source.Channel(r.SourceCh,
				&enqueueDelayingSyncEventHandler{
					enqueueDurationForJitter: time.Second * 2,
				}),
		)

	if err := m.Complete(r); err != nil {
		return err
	}

	return nil
}

// handleDeletion will handle the deletion path of the VDS secret:
// * revoking any associated outstanding leases
// * removing our finalizer
func (r *VaultDynamicSecretReconciler) handleDeletion(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) error {
	logger := log.FromContext(ctx)
	// We are ignoring errors inside `revokeLease`, otherwise we may fail to remove the finalizer.
	// Worst case at this point we will leave a dangling lease instead of a secret which
	// cannot be deleted. Events are emitted in these cases.
	r.revokeLease(ctx, o, "")

	objKey := client.ObjectKeyFromObject(o)
	r.SyncRegistry.Delete(objKey)
	r.BackOffRegistry.Delete(objKey)
	r.referenceCache.Remove(SecretTransformation, objKey)
	if controllerutil.ContainsFinalizer(o, vaultDynamicSecretFinalizer) {
		logger.Info("Removing finalizer")
		if controllerutil.RemoveFinalizer(o, vaultDynamicSecretFinalizer) {
			if err := r.Update(ctx, o); err != nil {
				logger.Error(err, "Failed to remove the finalizer")
				return err
			}
			logger.Info("Successfully removed the finalizer")
		}
	}
	return nil
}

// revokeLease revokes the VDS secret's lease.
// NOTE: Enabling revocation requires the VaultAuthMethod referenced by `o.Spec.VaultAuthRef` to have a policy
// that includes `path "sys/leases/revoke" { capabilities = ["update"] }`, otherwise this will fail with permission
// errors.
func (r *VaultDynamicSecretReconciler) revokeLease(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret, id string) {
	logger := log.FromContext(ctx)
	// Allow us to override the SecretLease in the event that we want to revoke an old lease.
	leaseID := id
	if leaseID == "" {
		leaseID = o.Status.SecretLease.ID
	}
	logger.Info("Revoking lease for credential ", "id", leaseID)
	c, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		logger.Error(err, "Failed to get client when revoking lease for ", "id", leaseID)
		return
	}
	if _, err = c.Write(ctx, vault.NewWriteRequest("/sys/leases/revoke", map[string]any{
		"lease_id": leaseID,
	})); err != nil {
		msg := "Failed to revoke lease"
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRevoke, msg+": %s", err)
		logger.Error(err, "Failed to revoke lease ", "id", leaseID)
	} else {
		msg := "Lease revoked"
		r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRevoke, msg+": %s", leaseID)
		logger.Info("Lease revoked ", "id", leaseID)
	}
}

// computePostSyncHorizon for a secretsv1beta1.VaultDynamicSecret. The duration
// computed varies depending on the "type" of Vault secret being synced. In the
// case the secret is from a "static-creds" role, the computed horizon will be
// greater than the secret rotation period/TTL. For all other types, the horizon
// is computed from the secret's lease duration, the o.Spec.RenewalPercent, minus
// some jitter offset. In the case where the secret has no lease duration, the
// horizon will be computed from o.Spec.RefreshAfter.
func (r *VaultDynamicSecretReconciler) computePostSyncHorizon(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) time.Duration {
	logger := log.FromContext(ctx).WithName("computePostSyncHorizon")
	var horizon time.Duration

	secretLease := o.Status.SecretLease
	d := getRotationDuration(o)
	if !o.Spec.AllowStaticCreds {
		horizon = computeDynamicHorizonWithJitter(d, o.Spec.RenewalPercent)
		logger.V(consts.LogLevelDebug).Info("Leased",
			"secretLease", secretLease, "horizon", horizon,
			"refreshAfter", o.Spec.RefreshAfter)
	} else {
		// TODO: handle the case where VSO missed the last rotation, check o.Status.StaticCredsMetaData.LastVaultRotation ?
		staticCredsMeta := o.Status.StaticCredsMetaData
		// the next sync should be scheduled in the future, Vault will be handling the
		// secret rotation. We need to get new secret data after it has been rotated, so
		// we always compute a horizon after staticCredsMeta.TTL.
		if !r.isStaticCreds(&staticCredsMeta) {
			horizon = 0
			logger.Info("Vault response data does not support static-creds semantics",
				"allowStaticCreds", o.Spec.AllowStaticCreds,
				"horizon", horizon,
				"status", o.Status,
			)
		} else {
			if d > 0 {
				horizon = d
				if staticCredsMeta.RotationPeriod > 0 {
					// give Vault an extra .5 seconds to perform the rotation if the case of a
					// non-scheduled rotation.
					horizon = d + 500*time.Millisecond
				}
			} else {
				horizon = time.Second * 1
			}
			_, jitter := computeMaxJitterWithPercent(staticCredsJitterHorizon, vdsJitterFactor)
			horizon += time.Duration(jitter)
			logger.V(consts.LogLevelDebug).Info("StaticCreds",
				"staticCredsMeta", staticCredsMeta, "horizon", horizon)
		}
	}

	return horizon
}

func getRotationDuration(o *secretsv1beta1.VaultDynamicSecret) time.Duration {
	var d time.Duration
	if o.Spec.AllowStaticCreds {
		d = time.Duration(o.Status.StaticCredsMetaData.TTL) * time.Second
	} else {
		d = time.Duration(o.Status.SecretLease.LeaseDuration) * time.Second
		if d <= 0 && o.Spec.RefreshAfter != "" {
			// we can ignore any parse errors since the min value is valid in this context in
			// addition we rely on the CRD API validators to prevent bogus duration strings
			// from ever making it here.
			d, _ = parseDurationString(o.Spec.RefreshAfter, ".spec.refreshAfter", 0)
		}
	}

	return d
}

// vaultClientCallback requests reconciliation of all VaultDynamicSecret
// instances that were synced with Client
func (r *VaultDynamicSecretReconciler) vaultClientCallback(ctx context.Context, c vault.Client) {
	logger := log.FromContext(ctx).WithName("vaultClientCallback")

	cacheKey, err := c.GetCacheKey()
	if err != nil {
		// should never get here
		logger.Error(err, "Invalid cache key, skipping syncing of VaultDynamicSecret instances")
		return
	}

	logger = logger.WithValues("cacheKey", cacheKey, "controller", "vds")
	var l secretsv1beta1.VaultDynamicSecretList
	if err := r.Client.List(ctx, &l, client.InNamespace(
		c.GetCredentialProvider().GetNamespace()),
	); err != nil {
		logger.Error(err, "Failed to list VaultDynamicSecret instances")
		return
	}

	if len(l.Items) == 0 {
		return
	}

	reqs := map[client.ObjectKey]empty{}
	for _, o := range l.Items {
		if o.Status.VaultClientMeta.CacheKey == "" {
			logger.V(consts.LogLevelWarning).Info("Skipping, cacheKey is empty",
				"object", client.ObjectKeyFromObject(&o))
			continue
		}

		curCacheKey := vault.ClientCacheKey(o.Status.VaultClientMeta.CacheKey)
		if ok, err := curCacheKey.SameParent(cacheKey); ok {
			evt := event.GenericEvent{
				Object: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: o.GetNamespace(),
						Name:      o.GetName(),
					},
				},
			}

			objKey := client.ObjectKeyFromObject(evt.Object)
			if _, ok := reqs[objKey]; !ok {
				// deduplicating is probably not necessary, but we do it just in case.
				reqs[objKey] = empty{}
				logger.V(consts.LogLevelDebug).Info("Enqueuing VaultDynamicSecret instance",
					"objKey", objKey)
				r.SyncRegistry.Add(objKey)
				logger.V(consts.LogLevelDebug).Info(
					"Sending GenericEvent to the SourceCh", "evt", evt)
				r.SourceCh <- evt
			}
		} else if err != nil {
			logger.V(consts.LogLevelWarning).Info(
				"Skipping, cacheKey error", "error", err)
		}
	}
}

func computeRotationTime(o *secretsv1beta1.VaultDynamicSecret) time.Time {
	var ts int64
	var horizon time.Duration
	d := getRotationDuration(o)
	if o.Spec.AllowStaticCreds {
		ts = o.Status.StaticCredsMetaData.LastVaultRotation
		horizon = d
	} else {
		ts = o.Status.LastRenewalTime
		horizon = computeStartRenewingAt(d, o.Spec.RenewalPercent)
	}

	return time.Unix(ts, 0).Add(horizon)
}

// computeRelativeHorizon returns the duration of the renewal window based on the
// lease's last renewal time relative to now.
// For non-static creds, return true if the associated lease is within its
// renewal window.
// For static creds, return true if the VDS object is in Vault the rotation
// window.
func computeRelativeHorizon(o *secretsv1beta1.VaultDynamicSecret) (time.Duration, bool) {
	ts := computeRotationTime(o)
	now := nowFunc()
	if o.Spec.AllowStaticCreds {
		return ts.Sub(now), now.Before(ts)
	} else {
		return ts.Sub(now), now.After(ts)
	}
}

// computeRelativeHorizonWithJitter returns the duration minus some random jitter
// of the renewal/rotation window based on the lease's last renewal time relative
// to now.
// For non-static creds, return true if the associated lease is within its
// renewal window.
// For static creds, return true if the VDS object is in Vault the rotation
// window.
// Use minHorizon if it is less than computed horizon.
func computeRelativeHorizonWithJitter(o *secretsv1beta1.VaultDynamicSecret, minHorizon time.Duration) (time.Duration, bool) {
	horizon, inWindow := computeRelativeHorizon(o)
	if horizon < minHorizon {
		horizon = minHorizon
	}
	if o.Spec.AllowStaticCreds {
		_, jitter := computeMaxJitterWithPercent(staticCredsJitterHorizon, vdsJitterFactor)
		horizon += time.Duration(jitter)
	} else {
		_, jitter := computeMaxJitterWithPercent(horizon, 0.05)
		horizon -= time.Duration(jitter)
	}
	return horizon, inWindow
}

func vaultStaticCredsMetaDataFromData(data map[string]any) (*secretsv1beta1.VaultStaticCredsMetaData, error) {
	var ret secretsv1beta1.VaultStaticCredsMetaData
	if v, ok := data["last_vault_rotation"]; ok && v != nil {
		ts, err := time.Parse(time.RFC3339Nano, v.(string))
		if err != nil {
			return nil, fmt.Errorf("invalid last_vault_rotation %w", err)
		}

		ret.LastVaultRotation = ts.Unix()
	}

	if v, ok := data["rotation_period"]; ok && v != nil {
		switch t := v.(type) {
		case json.Number:
			period, err := t.Int64()
			if err != nil {
				return nil, err
			}
			ret.RotationPeriod = period
		case int:
			ret.RotationPeriod = int64(t)
		default:
			return nil, errors.New("invalid rotation_period")
		}
	}

	if v, ok := data["rotation_schedule"]; ok && v != nil {
		if schedule, ok := v.(string); ok {
			ret.RotationSchedule = schedule
		}
	}

	if v, ok := data["ttl"]; ok && v != nil {
		switch t := v.(type) {
		case json.Number:
			ttl, err := t.Int64()
			if err != nil {
				return nil, err
			}
			ret.TTL = ttl
		case int:
			ret.TTL = int64(t)
		default:
			return nil, errors.New("invalid ttl")
		}
	}

	return &ret, nil
}
