// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
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
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultPKIFinalizer = "vaultpkisecrets.secrets.hashicorp.com/finalizer"

var minHorizon = time.Second * 1

// VaultPKISecretReconciler reconciles a VaultPKISecret object
type VaultPKISecretReconciler struct {
	client.Client
	Scheme                     *runtime.Scheme
	ClientFactory              vault.ClientFactory
	HMACValidator              helpers.HMACValidator
	Recorder                   record.EventRecorder
	SyncRegistry               *SyncRegistry
	BackOffRegistry            *BackOffRegistry
	referenceCache             ResourceReferenceCache
	GlobalTransformationOption *helpers.GlobalTransformationOption
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//
// required for rollout-restart
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
//

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state. It
// compares the state specified by the VaultPKISecret object against the
// actual cluster state, and then performs operations to make the cluster state
// reflect the state specified by the user.
func (r *VaultPKISecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.VaultPKISecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(consts.LogLevelDebug).Info("VaultPKISecret resource not found", "req", req)
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultPKISecret resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		return ctrl.Result{}, r.handleDeletion(ctx, o)
	}

	path := r.getPath(o.Spec)
	destinationExists, _ := helpers.CheckSecretExists(ctx, r.Client, o)
	// In the case where the secret should exist already, check that it does
	// before proceeding to issue a cert
	if !o.Spec.Destination.Create && !destinationExists {
		horizon := computeHorizonWithJitter(requeueDurationOnError)
		msg := fmt.Sprintf("Kubernetes secret %q does not exist yet, horizon=%s",
			o.Spec.Destination.Name, horizon)
		logger.Info(msg)
		o.Status.Error = consts.ReasonK8sClientError
		r.recordEvent(o, o.Status.Error, msg)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	// Since the status fields LastGeneration, SecretMAC, and LastRotation were added
	// together we can use the value of LastRotation to determine if VSO is running
	// with the expected schema. If the CRD schema has not been updated, then
	// LastRotation will always be 0, since an update to this field's value will be
	// dropped.
	// Note: LastRotation will be used in the future when the PKI expiry offset
	// can be expressed as a percentage.
	var schemaEpoch int
	if o.Status.LastRotation > 0 {
		schemaEpoch = 1
	}
	var syncReason string
	switch {
	case o.Status.SerialNumber == "":
		syncReason = consts.ReasonInitialSync
	case r.SyncRegistry.Has(req.NamespacedName):
		syncReason = consts.ReasonForceSync
	case schemaEpoch > 0 && o.GetGeneration() != o.Status.LastGeneration:
		syncReason = consts.ReasonResourceUpdated
	case o.Spec.Destination.Create && !destinationExists:
		logger.Info("Destination secret does not exist",
			"create", o.Spec.Clear,
			"destination", o.Spec.Destination.Name)
		syncReason = consts.ReasonInexistentDestination
	case destinationExists:
		if schemaEpoch > 0 {
			if matched, err := helpers.HMACDestinationSecret(ctx, r.Client,
				r.HMACValidator, o); err == nil && !matched {
				syncReason = consts.ReasonSecretDataDrift
			} else if err != nil {
				logger.Error(err, "Failed to HMAC destination secret")
			}
		}
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	if syncReason == "" {
		logger.V(consts.LogLevelTrace).Info("Check renewal window")
		horizon, inWindow := computePKIRenewalWindow(ctx, o, 0.05)
		if !inWindow {
			logger.Info("Not in renewal window", "horizon", horizon)
			return ctrl.Result{
				RequeueAfter: horizon,
			}, nil
		} else {
			syncReason = consts.ReasonInRenewalWindow
		}
	}

	// assume that status is always invalid
	o.Status.Valid = false
	logger.Info("Must sync", "reason", syncReason)
	c, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		logger.Error(err, "Get Vault client")
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	resp, err := c.Write(ctx, vault.NewWriteRequest(path, o.GetIssuerAPIData()))
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to issue certificate from Vault"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}

		r.SyncRegistry.Add(req.NamespacedName)
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		return ctrl.Result{
			RequeueAfter: entry.NextBackOff(),
		}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	certResp, err := vault.UnmarshalPKIIssueResponse(resp.Secret())
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to unmarshal PKI response"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	if certResp.SerialNumber == "" {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Invalid Vault secret data, serial_number cannot be empty"
		logger.Error(nil, msg)
		r.recordEvent(o, o.Status.Error, msg)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	data, err := resp.SecretK8sData(transOption)
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to marshal Vault secret data"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	// Fix ca_chain formatting since it's a slice
	if len(data["ca_chain"]) > 0 {
		data["ca_chain"] = []byte(strings.Join(certResp.CAChain, "\n"))
	}
	// If using data transformation (templates), avoid generating tls.key and tls.crt.
	if o.Spec.Destination.Type == corev1.SecretTypeTLS && len(transOption.KeyedTemplates) == 0 {
		data[corev1.TLSCertKey] = data["certificate"]
		// the ca_chain includes the issuing ca
		if len(data["ca_chain"]) > 0 {
			data[corev1.TLSCertKey] = append(data[corev1.TLSCertKey], []byte("\n")...)
			data[corev1.TLSCertKey] = append(data[corev1.TLSCertKey], []byte(data["ca_chain"])...)
		} else if len(data["issuing_ca"]) > 0 {
			data[corev1.TLSCertKey] = append(data[corev1.TLSCertKey], []byte("\n")...)
			data[corev1.TLSCertKey] = append(data[corev1.TLSCertKey], data["issuing_ca"]...)
		}
		data[corev1.TLSPrivateKeyKey] = data["private_key"]
	}

	if b, err := json.Marshal(data); err == nil {
		newMAC, err := r.HMACValidator.HMAC(ctx, r.Client, b)
		if err != nil {
			logger.Error(err, "HMAC data")
			o.Status.Error = consts.ReasonHMACDataError
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{
				RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
			}, nil
		}
		o.Status.SecretMAC = base64.StdEncoding.EncodeToString(newMAC)
	}

	if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
		logger.Error(err, "Sync secret")
		o.Status.Error = consts.ReasonSecretSyncError
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
		}, nil
	}

	reason := consts.ReasonSecretSynced
	if o.Status.SerialNumber != "" {
		reason = consts.ReasonSecretRotated
		// rollout-restart errors are not retryable
		// all error reporting is handled by helpers.HandleRolloutRestarts
		_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
	}

	// revoke the certificate on renewal
	if o.Spec.Revoke && o.Status.SerialNumber != "" {
		if err := r.revokeCertificate(ctx, logger, o); err != nil {
			logger.Error(err, "Certificate revocation")
			o.Status.Error = consts.ReasonCertificateRevocationError
			return ctrl.Result{
				RequeueAfter: computeHorizonWithJitter(requeueDurationOnError),
			}, nil
		}
	}

	o.Status.Valid = true
	o.Status.Error = ""
	o.Status.SerialNumber = certResp.SerialNumber
	o.Status.Expiration = certResp.Expiration
	o.Status.LastRotation = time.Now().Unix()
	if err := r.updateStatus(ctx, o); err != nil {
		logger.Error(err, "Failed to update the status")
		return ctrl.Result{}, err
	}

	r.SyncRegistry.Delete(req.NamespacedName)

	horizon, _ := computePKIRenewalWindow(ctx, o, .05)
	r.recordEvent(o, reason, fmt.Sprintf("Secret synced, horizon=%s", horizon))
	logger.Info("Successfully updated the secret", "horizon", horizon)
	return ctrl.Result{
		RequeueAfter: horizon,
	}, nil
}

func (r *VaultPKISecretReconciler) handleDeletion(ctx context.Context, o *secretsv1beta1.VaultPKISecret) error {
	objKey := client.ObjectKeyFromObject(o)
	r.SyncRegistry.Delete(objKey)
	r.BackOffRegistry.Delete(objKey)

	r.referenceCache.Remove(SecretTransformation, objKey)
	finalizerSet := controllerutil.ContainsFinalizer(o, vaultPKIFinalizer)
	logger := log.FromContext(ctx).WithName("handleDeletion").WithValues(
		"finalizer", vaultPKIFinalizer, "isSet", finalizerSet)
	logger.V(consts.LogLevelTrace).Info("In deletion")
	if finalizerSet {
		logger.V(consts.LogLevelDebug).Info("Delete finalizer")
		if controllerutil.RemoveFinalizer(o, vaultPKIFinalizer) {
			if err := r.Update(ctx, o); err != nil {
				logger.Error(err, "Failed to remove the finalizer")
				return err
			}
			logger.V(consts.LogLevelDebug).Info("Finalizers successfully removed")
		}
		if err := r.finalizePKI(ctx, logger, o); err != nil {
			logger.Error(err, "Failed")
		}

		return nil
	}

	return nil
}

func (r *VaultPKISecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = newResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultPKISecret{}).
		WithEventFilter(syncableSecretPredicate(r.SyncRegistry)).
		WithOptions(opts).
		Watches(
			&secretsv1beta1.SecretTransformation{},
			NewEnqueueRefRequestsHandlerST(r.referenceCache, r.SyncRegistry),
		).
		Watches(
			&corev1.Secret{},
			&enqueueOnDeletionRequestHandler{
				gvk: secretsv1beta1.GroupVersion.WithKind(VaultPKISecret.String()),
			},
			builder.WithPredicates(&secretsPredicate{}),
		).
		Complete(r)
}

func (r *VaultPKISecretReconciler) finalizePKI(ctx context.Context, l logr.Logger, s *secretsv1beta1.VaultPKISecret) error {
	l.Info("Finalizing VaultPKISecret")
	if s.Spec.Revoke {
		if err := r.revokeCertificate(ctx, l, s); err != nil {
			return err
		}
	}

	if !s.Spec.Destination.Create && s.Spec.Clear {
		if err := r.clearSecretData(ctx, l, s); err != nil {
			return err
		}
	}
	return nil
}

func (r *VaultPKISecretReconciler) clearSecretData(ctx context.Context, l logr.Logger, s *secretsv1beta1.VaultPKISecret) error {
	return helpers.SyncSecret(ctx, r.Client, s, nil)
}

func (r *VaultPKISecretReconciler) revokeCertificate(ctx context.Context, l logr.Logger, s *secretsv1beta1.VaultPKISecret) error {
	c, err := r.ClientFactory.Get(ctx, r.Client, s)
	if err != nil {
		return err
	}

	l.Info(fmt.Sprintf("Revoking certificate %q", s.Status.SerialNumber))

	if _, err := c.Write(ctx, vault.NewWriteRequest(fmt.Sprintf("%s/revoke", s.Spec.Mount), map[string]any{
		"serial_number": s.Status.SerialNumber,
	})); err != nil {
		l.Error(err, "Failed to revoke certificate", "serial_number", s.Status.SerialNumber)
		return err
	}

	return nil
}

func (r *VaultPKISecretReconciler) getPath(spec secretsv1beta1.VaultPKISecretSpec) string {
	parts := []string{spec.Mount}
	if spec.IssuerRef != "" {
		parts = append(parts, "issuer", spec.IssuerRef)
	} else {
		parts = append(parts, "issue")
	}
	parts = append(parts, spec.Role)

	return strings.Join(parts, "/")
}

func (r *VaultPKISecretReconciler) recordEvent(p *secretsv1beta1.VaultPKISecret, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !p.Status.Valid {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(p, eventType, reason, msg, i...)
}

func (r *VaultPKISecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultPKISecret) error {
	logger := log.FromContext(ctx)
	logger.V(consts.LogLevelTrace).Info("Update status called")

	metrics.SetResourceStatus("vaultpkisecret", o, o.Status.Valid)

	o.Status.LastGeneration = o.GetGeneration()
	if err := r.Status().Update(ctx, o); err != nil {
		msg := "Failed to update the resource's status"
		r.recordEvent(o, consts.ReasonStatusUpdateError, "%s: %s", msg, err)
		logger.Error(err, msg)
		return err
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultPKIFinalizer)
	return err
}

func computeExpirationTimePKI(o *secretsv1beta1.VaultPKISecret, offset int64) time.Time {
	return time.Unix(o.Status.Expiration-offset, 0)
}

func computePKIRenewalWindow(ctx context.Context, o *secretsv1beta1.VaultPKISecret,
	jitterPercent float64,
) (time.Duration, bool) {
	logger := log.FromContext(ctx).WithValues("expiryOffset", o.Spec.ExpiryOffset)
	if o.Status.LastRotation > 0 {
		// TODO: factor out lastRotation when we add support for spec.renewalPercent
		logger = logger.WithValues("lastRotation", time.Unix(o.Status.LastRotation, 0))
	}

	offset, err := parseDurationString(o.Spec.ExpiryOffset, ".spec.expiryOffset", 0)
	if err != nil {
		logger.Info("Warning: tolerating invalid expiryOffset",
			"err", err, "effectiveOffset", offset)
	}

	now := nowFunc()
	rotationTime := computeExpirationTimePKI(o, int64(offset.Seconds()))
	horizon := rotationTime.Sub(now)
	var inWindow bool
	if isInWindow(now, rotationTime) || horizon < minHorizon {
		horizon = minHorizon
		inWindow = true
	}

	// compute the horizon for the next renewal check add/subtract some jitter to
	// ensure that the next scheduled check will be in the renewal window.
	_, jitter := computeMaxJitterDurationWithPercent(horizon, jitterPercent)
	if offset > 0 || inWindow {
		horizon += jitter
	} else {
		horizon -= jitter
	}

	logger.V(consts.LogLevelDebug).WithValues(
		"expiresWhen", rotationTime, "now", now,
		"serialNumber", o.Status.SerialNumber,
		"horizon", horizon).Info("Computed certificate renewal window with spec.expiryOffset")

	return horizon, inWindow
}
