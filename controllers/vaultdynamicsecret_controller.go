// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"
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

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const (
	vaultDynamicSecretFinalizer = "vaultdynamicsecret.secrets.hashicorp.com/finalizer"
)

// VaultDynamicSecretReconciler reconciles a VaultDynamicSecret object
type VaultDynamicSecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ClientFactory vault.ClientFactory
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
	logger := log.FromContext(ctx)

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

	o := &secretsv1alpha1.VaultDynamicSecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "error getting resource from k8s", "obj", o)
		return ctrl.Result{}, err
	}
	// Add a finalizer on the VDS resource if we intend to Revoke on cleanup path or lease renewal.
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

	var doRolloutRestart bool
	leaseID := o.Status.SecretLease.ID
	if leaseID != "" {
		if r.runtimePodUID != "" && r.runtimePodUID != o.Status.LastRuntimePodUID {
			// don't take part in the thundering herd on start up,
			// and the lease is still within the renewal window.
			if !inRenewalWindow(o) {
				leaseDuration := time.Duration(o.Status.SecretLease.LeaseDuration) * time.Second
				horizon := computeDynamicHorizonWithJitter(leaseDuration, o.Spec.RenewalPercent)
				if err := r.updateStatus(ctx, o); err != nil {
					return ctrl.Result{}, err
				}
				r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
					"Not in renewal window after transitioning to a new leader/pod, lease_id=%s, horizon=%s",
					leaseID, horizon)
				return ctrl.Result{RequeueAfter: horizon}, nil
			}
		}

		vClient, err := r.ClientFactory.Get(ctx, r.Client, o)
		if err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
				"Failed to get Vault client: %s, lease_id=%s", err, leaseID)
			return ctrl.Result{}, err
		}

		// Renew the lease and return from Reconcile if the lease is succesfully renewed.
		if secretLease, err := r.renewLease(ctx, vClient, o); err == nil {
			if !r.isRenewableLease(secretLease, o) {
				return ctrl.Result{}, nil
			}

			if secretLease.ID != leaseID {
				// the new lease ID does not match, this should never happen.
				err := fmt.Errorf("lease ID changed after renewal, expected=%s, actual=%s", leaseID, secretLease.ID)
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewal, err.Error())
				return ctrl.Result{}, err
			}

			o.Status.SecretLease = *secretLease
			o.Status.LastRenewalTime = time.Now().Unix()
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
			// The secretLease was not renewed or failed, continue through Reconcile and do a rollout restart.
			doRolloutRestart = true
			if e, ok := err.(*LeaseTruncatedError); ok || e != nil && errors.As(err, &e) {
				r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRenewal,
					"Lease renewal duration was truncated from %ds to %ds, requesting new credentials", e.Expected, e.Actual)
			} else if !isLeaseNotfoundError(err) {
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewalError,
					"Could not renew lease, lease_id=%s, err=%s", leaseID, err)
			}
		}
	}

	vClient, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault client: %s, lease_id=%s", err, leaseID)
		return ctrl.Result{}, err
	}
	oldLease := o.Status.SecretLease

	secretLease, err := r.syncSecret(ctx, vClient, o)
	if err != nil {
		return ctrl.Result{}, err
	}

	o.Status.SecretLease = *secretLease
	o.Status.LastRenewalTime = time.Now().Unix()
	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}
	// Revoke the existing Lease if it did exist before and we just renewed it.
	if o.Spec.Revoke && oldLease.ID != "" && oldLease.Renewable {
		r.revokeLease(ctx, o, oldLease.ID)
	}

	reason := consts.ReasonSecretSynced
	leaseDuration := time.Duration(secretLease.LeaseDuration) * time.Second
	horizon := computeDynamicHorizonWithJitter(leaseDuration, o.Spec.RenewalPercent)
	r.Recorder.Eventf(o, corev1.EventTypeNormal, reason,
		"Secret synced, lease_id=%s, horizon=%s", secretLease.ID, horizon)

	if doRolloutRestart {
		reason = consts.ReasonSecretRotated
		// rollout-restart errors are not retryable
		// all error reporting is handled by helpers.HandleRolloutRestarts
		_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
	}

	if !r.isRenewableLease(secretLease, o) {
		return ctrl.Result{}, nil
	}

	return ctrl.Result{RequeueAfter: horizon}, nil
}

func (r *VaultDynamicSecretReconciler) isRenewableLease(resp *secretsv1alpha1.VaultSecretLease, o *secretsv1alpha1.VaultDynamicSecret) bool {
	if !resp.Renewable {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRenewal,
			"Lease is not renewable, info=%#v", resp)
		return false
	}
	return true
}

func (r *VaultDynamicSecretReconciler) syncSecret(ctx context.Context, vClient vault.Client, o *secretsv1alpha1.VaultDynamicSecret) (*secretsv1alpha1.VaultSecretLease, error) {
	path := fmt.Sprintf("%s/%s", o.Spec.Mount, o.Spec.Path)
	resp, err := vClient.Read(ctx, path)
	if err != nil {
		return nil, err
	}

	if resp == nil {
		return nil, fmt.Errorf("nil response from vault for path %s", path)
	}

	data, err := vault.MarshalSecretData(resp)
	if err != nil {
		return nil, err
	}

	if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
		return nil, err
	}

	return r.getVaultSecretLease(resp), nil
}

func (r *VaultDynamicSecretReconciler) updateStatus(ctx context.Context, o *secretsv1alpha1.VaultDynamicSecret) error {
	if r.runtimePodUID != "" {
		o.Status.LastRuntimePodUID = r.runtimePodUID
	}
	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}
	return nil
}

func (r *VaultDynamicSecretReconciler) getVaultSecretLease(resp *api.Secret) *secretsv1alpha1.VaultSecretLease {
	return &secretsv1alpha1.VaultSecretLease{
		ID:            resp.LeaseID,
		LeaseDuration: resp.LeaseDuration,
		Renewable:     resp.Renewable,
		RequestID:     resp.RequestID,
	}
}

func (r *VaultDynamicSecretReconciler) renewLease(ctx context.Context, c vault.Client, o *secretsv1alpha1.VaultDynamicSecret) (*secretsv1alpha1.VaultSecretLease, error) {
	resp, err := c.Write(ctx, "/sys/leases/renew", map[string]interface{}{
		"lease_id":  o.Status.SecretLease.ID,
		"increment": o.Status.SecretLease.LeaseDuration,
	})
	if err != nil {
		return nil, err
	}
	// The renewal duration can come back as less than the requested increment
	// if the time remaining on max_ttl is less than the increment. In this case
	// return an error so new credentials are acquired.
	if resp.LeaseDuration < o.Status.SecretLease.LeaseDuration {
		return r.getVaultSecretLease(resp), &LeaseTruncatedError{
			Expected: o.Status.SecretLease.LeaseDuration,
			Actual:   resp.LeaseDuration,
		}
	}

	return r.getVaultSecretLease(resp), nil
}

func (r *VaultDynamicSecretReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultDynamicSecret) error {
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
		For(&secretsv1alpha1.VaultDynamicSecret{}).
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
func (r *VaultDynamicSecretReconciler) handleDeletion(ctx context.Context, o *secretsv1alpha1.VaultDynamicSecret) error {
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
func (r *VaultDynamicSecretReconciler) revokeLease(ctx context.Context, o *secretsv1alpha1.VaultDynamicSecret, id string) {
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
	if _, err = c.Write(ctx, "/sys/leases/revoke", map[string]interface{}{
		"lease_id": leaseID,
	}); err != nil {
		msg := "Failed to revoke lease"
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretLeaseRevoke, msg+": %s", err)
		logger.Error(err, "Failed to revoke lease ", "id", leaseID)
	} else {
		msg := "Lease revoked"
		r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonSecretLeaseRevoke, msg+": %s", leaseID)
		logger.Info("Lease revoked ", "id", leaseID)
	}
}

// inRenewalWindow checks if the specified percentage of the VDS lease duration
// has elapsed
func inRenewalWindow(vds *secretsv1alpha1.VaultDynamicSecret) bool {
	renewalPercent := capRenewalPercent(vds.Spec.RenewalPercent)
	leaseDuration := time.Duration(vds.Status.SecretLease.LeaseDuration) * time.Second
	startRenewingAt := time.Duration(float64(leaseDuration.Nanoseconds()) * float64(renewalPercent) / 100)

	ts := time.Unix(vds.Status.LastRenewalTime, 0).Add(startRenewingAt)
	return time.Now().After(ts)
}
