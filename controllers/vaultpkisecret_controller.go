// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultPKIFinalizer = "vaultpkisecrets.secrets.hashicorp.com/finalizer"

// VaultPKISecretReconciler reconciles a VaultPKISecret object
type VaultPKISecretReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
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

	s := &secretsv1alpha1.VaultPKISecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, s); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultPKISecret resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	path := r.getPath(s.Spec)
	logger = logger.WithValues("vault_path", path, "dest", s.Spec.Dest)

	if s.GetDeletionTimestamp() != nil {
		if err := r.handleDeletion(ctx, logger, s); err != nil {
			s.Status.Valid = false
			s.Status.Error = reasonK8sClientError
			msg := "Failed to handle deletion"
			logger.Error(err, msg)
			r.recordEvent(s, s.Status.Error, msg+": %s", err)
			if err := r.updateStatus(ctx, s); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
	}

	var expiryOffset time.Duration
	if s.Spec.ExpiryOffset != "" {
		d, err := time.ParseDuration(s.Spec.ExpiryOffset)
		if err != nil {
			s.Status.Valid = false
			s.Status.Error = reasonInvalidConfiguration
			msg := fmt.Sprintf("Failed to parse ExpiryOffset %q", s.Spec.ExpiryOffset)
			logger.Error(err, msg)
			r.recordEvent(s, s.Status.Error, msg+": %s", err)
			if err := r.updateStatus(ctx, s); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, err
		}
		expiryOffset = d
	}

	if !s.Status.Renew && s.Status.SerialNumber != "" {
		// logger.Info("Certificate already issued", "serial_number", s.Status.SerialNumber)
		// check if within the certificate renewal window
		if expiryOffset > 0 {
			if checkPKICertExpiry(s.Status.Expiration, expiryOffset) {
				logger.Info("Setting renewal for certificate expiry")
				s.Status.Renew = true
				if err := r.Status().Update(ctx, s); err != nil {
					logger.Error(err, "Failed to update the status")
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, nil
			}
		}

		return ctrl.Result{
			RequeueAfter: expiryOffset,
		}, nil
	}

	// the secret should already be provisioned, the operator does
	// not support dynamically creating secrets yet.
	sec, err := r.getSecret(ctx, logger, s)
	if err != nil {
		msg := fmt.Sprintf("Kubernetes secret %s/%s does not exist yet", s.Namespace, s.Spec.Dest)
		logger.Info(msg)
		s.Status.Valid = false
		s.Status.Error = reasonK8sClientError
		r.recordEvent(s, s.Status.Error, msg)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, nil
	}

	vc, err := getVaultConfig(ctx, r.Client, s)
	if err != nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Failed to retrieve Vault config"
		logger.Error(err, msg)
		r.recordEvent(s, s.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	c, err := getVaultClient(ctx, vc, r.Client)
	if err != nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Failed to get Vault client"
		logger.Error(err, msg)
		r.recordEvent(s, s.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	resp, err := c.Logical().WriteWithContext(ctx, path, s.GetIssuerAPIData())
	if err != nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Failed to issue certificate from Vault"
		logger.Error(err, msg)
		r.recordEvent(s, s.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if resp == nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := fmt.Sprintf("Empty Vault secret at path %s", path)
		logger.Error(nil, msg)
		r.recordEvent(s, s.Status.Error, msg)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{
			RequeueAfter: time.Second * 30,
		}, nil
	}

	certResp, err := vault.UnmarshalPKIIssueResponse(resp)
	if err != nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Failed to unmarshal PKI response"
		logger.Error(err, msg)
		r.recordEvent(s, s.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if certResp.SerialNumber == "" {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Invalid Vault secret data, serial_number cannot be empty"
		logger.Error(nil, msg)
		r.recordEvent(s, s.Status.Error, msg)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	data, err := vault.MarshalSecretData(resp)
	if err != nil {
		s.Status.Valid = false
		s.Status.Error = reasonVaultClientError
		msg := "Failed to marshal Vault secret data"
		logger.Error(err, msg)
		r.recordEvent(s, s.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, s); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}
	sec.Data = data
	if err := r.Client.Update(ctx, sec); err != nil {
		logger.Error(err, "Error updating the secret")
		return ctrl.Result{}, err
	}

	logger.Info("Successfully updated the secret")

	// revoke the certificate on renewal
	if s.Spec.Revoke && s.Status.Renew && s.Status.SerialNumber != "" {
		if err := r.revokeCertificate(ctx, logger, s); err != nil {
			return ctrl.Result{}, err
		}
	}

	s.Status.Valid = true
	s.Status.Error = ""
	s.Status.SerialNumber = certResp.SerialNumber
	s.Status.Expiration = certResp.Expiration
	s.Status.Renew = false
	if err := r.updateStatus(ctx, s); err != nil {
		logger.Error(err, "Failed to update the status")
		return ctrl.Result{}, err
	}

	if err := r.addFinalizer(ctx, logger, s); err != nil {
		return ctrl.Result{}, err
	}

	// TODO:
	// set ctrl.Result.Requeue to true with RequeueAfter being the credential (expiry TTL - some offset)
	//return ctrl.Result{
	//	RequeueAfter: refAfter,
	//}, err

	return ctrl.Result{}, nil
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
		Complete(r)
}

func (r *VaultPKISecretReconciler) finalizePKI(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	l.Info("Finalizing VaultPKISecret")
	if s.Spec.Revoke {
		if err := r.revokeCertificate(ctx, l, s); err != nil {
			return err
		}
	}

	if s.Spec.Clear {
		if err := r.clearSecretData(ctx, l, s); err != nil {
			return err
		}
	}
	return nil
}

func (r *VaultPKISecretReconciler) getSecret(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) (*corev1.Secret, error) {
	key := types.NamespacedName{
		Namespace: s.Namespace,
		Name:      s.Spec.Dest,
	}

	sec := &corev1.Secret{}
	if err := r.Client.Get(ctx, key, sec); err != nil {
		return nil, err
	}

	return sec, nil
}

func (r *VaultPKISecretReconciler) clearSecretData(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	l.Info("Clearing the secret's data", "name", s.Spec.Dest)
	sec, err := r.getSecret(ctx, l, s)
	if err != nil {
		return err
	}

	sec.Data = nil

	return r.Client.Update(ctx, sec)
}

func (r *VaultPKISecretReconciler) revokeCertificate(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKISecret) error {
	vc, err := getVaultConfig(ctx, r.Client, s)
	if err != nil {
		return err
	}

	c, err := getVaultClient(ctx, vc, r.Client)
	if err != nil {
		return err
	}

	l.Info(fmt.Sprintf("Revoking certificate %q", s.Status.SerialNumber))

	if _, err := c.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/revoke", s.Spec.Mount), map[string]interface{}{
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
	logger.Info("Updating status", "status", p.Status)
	metrics.SetResourceStatus("vaultpkisecret", p, p.Status.Valid)
	if err := r.Status().Update(ctx, p); err != nil {
		msg := "Failed to update the resource's status"
		r.recordEvent(p, reasonStatusUpdateError, "%s: %s", msg, err)
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
