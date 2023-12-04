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

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
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

// VaultDynamicSecretReconciler reconciles a VaultDynamicSecret object
type VaultDynamicSecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.ClientFactory
	HMACValidator helpers.HMACValidator
	// runtimePodUID should always be set when updating resource's Status.
	// This is done via the downwardAPI. We get the current Pod's UID from either the
	// OPERATOR_POD_UID environment variable, or the /var/run/podinfo/uid file; in that order.
	runtimePodUID types.UID
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultdynamicsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//
// required for rollout-restart
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
//
// needed for managing cached Clients, duplicated in vaultconnection_controller.go
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch

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
	// Add a finalizer on the VDS resource if we intend to Revoke on cleanup path.
	// Otherwise, there isn't a need for it since we are not managing anything on deletion.
	if o.Spec.Revoke {
		if o.GetDeletionTimestamp() == nil {
			if err := r.addFinalizer(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			logger.Info("Got deletion timestamp", "obj", o)
			return ctrl.Result{}, r.handleDeletion(ctx, o)
		}
	}

	// doSync indicates that the controller should perform the secret sync,
	// skipping any lease renewals.
	doSync := o.GetGeneration() != o.Status.LastGeneration
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

	vClient, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault client: %s, lease_id=%s", err, leaseID)
		_, jitter := computeMaxJitterWithPercent(requeueDurationOnError, 0.5)
		return ctrl.Result{
			RequeueAfter: requeueDurationOnError + time.Duration(jitter),
		}, nil
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
			} else if !isLeaseNotfoundError(err) {
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewalError,
					"Could not renew lease, lease_id=%s, err=%s", leaseID, err)
			}
		}
	}

	reason := consts.ReasonSecretSynced
	if o.Status.LastGeneration > 0 {
		reason = consts.ReasonSecretRotated
	}

	// sync the secret
	secretLease, staticCredsUpdated, err := r.syncSecret(ctx, vClient, o)
	if err != nil {
		_, jitter := computeMaxJitterWithPercent(requeueDurationOnError, 0.5)
		return ctrl.Result{
			RequeueAfter: requeueDurationOnError + time.Duration(jitter),
		}, nil
	}

	doRolloutRestart := (doSync && o.Status.LastGeneration > 1) || staticCredsUpdated
	o.Status.SecretLease = *secretLease
	o.Status.LastRenewalTime = nowFunc().Unix()
	o.Status.LastGeneration = o.GetGeneration()
	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	horizon := r.computePostSyncHorizon(ctx, o)
	r.Recorder.Eventf(o, corev1.EventTypeNormal, reason,
		"Secret synced, lease_id=%q, horizon=%s", secretLease.ID, horizon)

	if doRolloutRestart {
		// rollout-restart errors are not retryable
		// all error reporting is handled by helpers.HandleRolloutRestarts
		_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
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

func (r *VaultDynamicSecretReconciler) syncSecret(ctx context.Context, c vault.ClientBase, o *secretsv1beta1.VaultDynamicSecret) (*secretsv1beta1.VaultSecretLease, bool, error) {
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
	if params != nil {
		if !(method == http.MethodPost || method == http.MethodPut) {
			log.FromContext(ctx).V(consts.LogLevelWarning).Info(
				"Params provided, ignoring specified method",
				"requestHTTPMethod", o.Spec.RequestHTTPMethod)
		}
		method = http.MethodPut
	}
	if method == "" {
		method = http.MethodGet
	}

	switch method {
	case http.MethodPut, http.MethodPost:
		resp, err = c.Write(ctx, vault.NewWriteRequest(path, params))
	case http.MethodGet:
		resp, err = c.Read(ctx, vault.NewReadRequest(path, nil))
	default:
		return nil, false, fmt.Errorf("unsupported HTTP method %q for sync", method)
	}

	if err != nil {
		return nil, false, err
	}

	if resp == nil {
		return nil, false, fmt.Errorf("nil response from vault for path %s", path)
	}

	data, err := resp.SecretK8sData()
	if err != nil {
		return nil, false, err
	}

	secretLease := r.getVaultSecretLease(resp.Secret())
	if !r.isRenewableLease(secretLease, o, true) && o.Spec.AllowStaticCreds {
		respData := resp.Data()
		if v, ok := respData["last_vault_rotation"]; ok && v != nil {
			ts, err := time.Parse(time.RFC3339Nano, v.(string))
			if err == nil {
				o.Status.StaticCredsMetaData.LastVaultRotation = ts.Unix()
			}
		}
		if v, ok := respData["rotation_period"]; ok && v != nil {
			switch t := v.(type) {
			case json.Number:
				period, err := t.Int64()
				if err == nil {
					o.Status.StaticCredsMetaData.RotationPeriod = period
				}
			}
		}
		if v, ok := respData["rotation_schedule"]; ok && v != nil {
			if schedule, ok := v.(string); ok && v != nil {
				o.Status.StaticCredsMetaData.RotationSchedule = schedule
			}
		}
		if v, ok := respData["ttl"]; ok && v != nil {
			switch t := v.(type) {
			case json.Number:
				ttl, err := t.Int64()
				if err == nil {
					o.Status.StaticCredsMetaData.TTL = ttl
				}
			}
		}

		if r.isStaticCreds(&o.Status.StaticCredsMetaData) {
			dataToMAC := maps.Clone(data)
			for _, k := range []string{"ttl", "rotation_schedule", "rotation_period", "last_vault_rotation", "_raw"} {
				delete(dataToMAC, k)
			}

			macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.Client, r.HMACValidator, o, dataToMAC)
			if err != nil {
				return nil, false, err
			}

			o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)
			if macsEqual {
				return secretLease, false, nil
			}
		}
	}

	if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
		return nil, false, err
	}

	return secretLease, true, nil
}

func (r *VaultDynamicSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) error {
	if r.runtimePodUID != "" {
		o.Status.LastRuntimePodUID = r.runtimePodUID
	}
	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}

	return nil
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

func (r *VaultDynamicSecretReconciler) addFinalizer(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) error {
	if !controllerutil.ContainsFinalizer(o, vaultDynamicSecretFinalizer) {
		controllerutil.AddFinalizer(o, vaultDynamicSecretFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultDynamicSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultDynamicSecret{}).
		WithOptions(opts).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func isLeaseNotfoundError(err error) bool {
	if respErr, ok := err.(*api.ResponseError); ok && respErr != nil {
		if respErr.StatusCode == http.StatusBadRequest {
			return len(respErr.Errors) == 1 && respErr.Errors[0] == "lease not found"
		}
	}
	return false
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
// some jitter offset.
func (r *VaultDynamicSecretReconciler) computePostSyncHorizon(ctx context.Context, o *secretsv1beta1.VaultDynamicSecret) time.Duration {
	logger := log.FromContext(ctx).WithName("computePostSyncHorizon")
	var horizon time.Duration

	secretLease := o.Status.SecretLease
	if !o.Spec.AllowStaticCreds {
		leaseDuration := time.Duration(secretLease.LeaseDuration) * time.Second
		horizon = computeDynamicHorizonWithJitter(leaseDuration, o.Spec.RenewalPercent)
		logger.V(consts.LogLevelDebug).Info("Leased",
			"secretLease", secretLease, "horizon", horizon)
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
			if staticCredsMeta.TTL > 0 {
				// give Vault an extra .5 seconds to perform the rotation
				horizon = time.Duration(staticCredsMeta.TTL)*time.Second + 500*time.Millisecond
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

func computeRotationTime(o *secretsv1beta1.VaultDynamicSecret) time.Time {
	var ts int64
	var horizon time.Duration
	if o.Spec.AllowStaticCreds {
		ts = o.Status.StaticCredsMetaData.LastVaultRotation
		horizon = time.Duration(o.Status.StaticCredsMetaData.TTL) * time.Second
	} else {
		ts = o.Status.LastRenewalTime
		horizon = computeStartRenewingAt(
			time.Duration(o.Status.SecretLease.LeaseDuration)*time.Second, o.Spec.RenewalPercent)
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
