// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/operator-framework/operator-lib/handler"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultPKIFinalizer = "vaultpkisecrets.secrets.hashicorp.com/finalizer"

// VaultPKISecretReconciler reconciles a VaultPKISecret object
type VaultPKISecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory vault.ClientFactory
	Recorder      record.EventRecorder
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state. It
// compares the state specified by the VaultPKISecret object against the
// actual cluster state, and then performs operations to make the cluster state
// reflect the state specified by the user.
func (r *VaultPKISecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1alpha1.VaultPKISecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultPKISecret resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	path := r.getPath(o.Spec)
	if o.GetDeletionTimestamp() != nil {
		if err := r.handleDeletion(ctx, logger, o); err != nil {
			o.Status.Valid = false
			o.Status.Error = consts.ReasonK8sClientError
			msg := "Failed to handle deletion"
			logger.Error(err, msg)
			r.recordEvent(o, o.Status.Error, msg+": %s", err)
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
	}

	// assume that status is always invalid
	o.Status.Valid = false

	var expiryOffset time.Duration
	if o.Spec.ExpiryOffset != "" {
		d, err := time.ParseDuration(o.Spec.ExpiryOffset)
		if err != nil {
			o.Status.Error = consts.ReasonInvalidConfiguration
			msg := fmt.Sprintf("Failed to parse ExpiryOffset %q", o.Spec.ExpiryOffset)
			logger.Error(err, msg)
			r.recordEvent(o, o.Status.Error, msg+": %s", err)
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
		expiryOffset = d
	}

	timeToRenew := false
	if o.Status.SerialNumber != "" {
		if expiryOffset > 0 {
			// check if within the certificate renewal window
			if checkPKICertExpiry(o.Status.Expiration, expiryOffset) {
				logger.Info("Setting renewal for certificate expiry")
				timeToRenew = true
			} else {
				// Not time to renew yet, requeue closer to (Expiration - expiryOffset)
				return ctrl.Result{
					RequeueAfter: computeHorizonWithJitter(getRenewTime(o.Status.Expiration, expiryOffset)),
				}, nil
			}
		} else {
			// Since renewal was not requested (ExpiryOffset: 0), return without
			// requeuing
			return ctrl.Result{}, nil
		}
	}

	// In the case where the secret should exist already, check that it does
	// before proceeding to issue a cert
	if !o.Spec.Destination.Create {
		exists, err := helpers.CheckSecretExists(ctx, r.Client, o)
		if err != nil {
			msg := fmt.Sprintf("Error checking if the destination secret %q exists: %s",
				o.Spec.Destination.Name, err)
			o.Status.Error = consts.ReasonK8sClientError
			r.recordEvent(o, o.Status.Error, msg)
			if err := r.updateStatus(ctx, o); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}

		if !exists {
			horizon := computeHorizonWithJitter(time.Second * 10)
			msg := fmt.Sprintf("Kubernetes secret %q does not exist yet, retry_horizon %s",
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
	}

	c, err := r.ClientFactory.GetClient(ctx, r.Client, o)
	if err != nil {
		return ctrl.Result{}, err
	}

	resp, err := c.Write(ctx, path, o.GetIssuerAPIData())
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to issue certificate from Vault"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if resp == nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := fmt.Sprintf("Empty Vault secret at path %s", path)
		logger.Error(nil, msg)
		r.recordEvent(o, o.Status.Error, msg)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: time.Second * 30,
		}, nil
	}

	certResp, err := vault.UnmarshalPKIIssueResponse(resp)
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to unmarshal PKI response"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if certResp.SerialNumber == "" {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Invalid Vault secret data, serial_number cannot be empty"
		logger.Error(nil, msg)
		r.recordEvent(o, o.Status.Error, msg)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	data, err := vault.MarshalSecretData(resp)
	if err != nil {
		o.Status.Error = consts.ReasonK8sClientError
		msg := "Failed to marshal Vault secret data"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}
	if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
		return ctrl.Result{}, err
	}

	// revoke the certificate on renewal
	if o.Spec.Revoke && timeToRenew && o.Status.SerialNumber != "" {
		if err := r.revokeCertificate(ctx, logger, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	o.Status.Valid = true
	o.Status.Error = ""
	o.Status.SerialNumber = certResp.SerialNumber
	o.Status.Expiration = certResp.Expiration
	if err := r.updateStatus(ctx, o); err != nil {
		logger.Error(err, "Failed to update the status")
		return ctrl.Result{}, err
	}

	if err := r.addFinalizer(ctx, logger, o); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Successfully updated the secret")
	r.recordEvent(o, consts.ReasonAccepted, "Secret synced")

	return ctrl.Result{
		RequeueAfter: computeHorizonWithJitter(getRenewTime(o.Status.Expiration, expiryOffset)),
	}, nil
}

func (r *VaultPKISecretReconciler) handleDeletion(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	l.Info("In deletion")
	if controllerutil.ContainsFinalizer(s, vaultPKIFinalizer) {
		if err := r.finalizePKI(ctx, l, s); err != nil {
			l.Error(err, "finalizer failed")
			// TODO: decide how to handle a failed finalizer
			// return ctrl.Result{}, nil
		}

		l.Info("Removing finalizer")
		controllerutil.RemoveFinalizer(s, vaultPKIFinalizer)
		if err := r.Update(ctx, s); err != nil {
			l.Error(err, "failed to remove finalizer")
			return err
		}
		l.Info("Successfully removed the finalizer")

		return nil
	}

	return nil
}

func (r *VaultPKISecretReconciler) addFinalizer(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	if !controllerutil.ContainsFinalizer(s, vaultPKIFinalizer) {
		controllerutil.AddFinalizer(s, vaultPKIFinalizer)
		if err := r.Client.Update(ctx, s); err != nil {
			l.Error(err, "error updating VaultPKISecret resource")
			return err
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultPKISecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultPKISecret{}).
		// Add metrics for create/update/delete of the resource
		Watches(&source.Kind{Type: &secretsv1alpha1.VaultPKISecret{}},
			&handler.InstrumentedEnqueueRequestForObject{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *VaultPKISecretReconciler) finalizePKI(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
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

func (r *VaultPKISecretReconciler) clearSecretData(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	return helpers.SyncSecret(ctx, r.Client, s, nil)
}

func (r *VaultPKISecretReconciler) revokeCertificate(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	c, err := r.ClientFactory.GetClient(ctx, r.Client, s)
	if err != nil {
		return err
	}

	l.Info(fmt.Sprintf("Revoking certificate %q", s.Status.SerialNumber))

	if _, err := c.Write(ctx, fmt.Sprintf("%s/revoke", s.Spec.Mount), map[string]interface{}{
		"serial_number": s.Status.SerialNumber,
	}); err != nil {
		l.Error(err, "Failed to revoke certificate", "serial_number", s.Status.SerialNumber)
		return err
	}

	return nil
}

func (r *VaultPKISecretReconciler) getPath(spec secretsv1alpha1.VaultPKISecretSpec) string {
	parts := []string{spec.Mount}
	if spec.IssuerRef != "" {
		parts = append(parts, "issuer", spec.IssuerRef)
	} else {
		parts = append(parts, "issue")
	}
	parts = append(parts, spec.Name)

	return strings.Join(parts, "/")
}

func (r *VaultPKISecretReconciler) recordEvent(p *secretsv1alpha1.VaultPKISecret, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !p.Status.Valid {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(p, eventType, reason, msg, i...)
}

func (r *VaultPKISecretReconciler) updateStatus(ctx context.Context, p *secretsv1alpha1.VaultPKISecret) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("vaultpkisecret", p, p.Status.Valid)
	if err := r.Status().Update(ctx, p); err != nil {
		msg := "Failed to update the resource's status"
		r.recordEvent(p, consts.ReasonStatusUpdateError, "%s: %s", msg, err)
		logger.Error(err, msg)
		return err
	}

	return nil
}

func checkPKICertExpiry(expiration int64, offset time.Duration) bool {
	expiry := time.Unix(expiration-int64(offset.Seconds()), 0)
	now := time.Now()

	return now.After(expiry)
}

func getRenewTime(expiration int64, offset time.Duration) time.Duration {
	renewTime := time.Unix(expiration-int64(offset.Seconds()), 0)
	return renewTime.Sub(time.Now())
}
