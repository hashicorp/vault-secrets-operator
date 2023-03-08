// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultPKIFinalizer = "vaultpkisecrets.secrets.hashicorp.com/finalizer"

// VaultPKISecretReconciler reconciles a VaultPKISecret object
type VaultPKISecretReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	ClientFactory vault.ClientFactory
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkisecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultPKISecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *VaultPKISecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	s := &secretsv1alpha1.VaultPKISecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, s); err != nil {
		if apierrors.IsNotFound(err) {
			// logger.Info(fmt.Sprintf("Request not found %#v", req))
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", s)
		return ctrl.Result{}, err
	}

	path := r.getPath(s.Spec)
	if s.GetDeletionTimestamp() != nil {
		if err := r.handleDeletion(ctx, logger, s); err != nil {
			return ctrl.Result{}, err
		}
	}

	var expiryOffset time.Duration
	if s.Spec.ExpiryOffset != "" {
		d, err := time.ParseDuration(s.Spec.ExpiryOffset)
		if err != nil {
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
	if !s.Spec.Destination.Create {
		exists, err := helpers.CheckSecretExists(ctx, r.Client, s)
		if err != nil {
			return ctrl.Result{}, err
		}

		if !exists {
			horizon, _ := computeHorizonWithJitter(time.Second * 10)
			logger.Info("Kubernetes secret does not exist yet",
				"name", s.Spec.Destination.Name, "retry_horizon", horizon)
			return ctrl.Result{
				RequeueAfter: horizon,
			}, nil
		}
	}

	c, err := r.ClientFactory.GetClient(ctx, r.Client, s)
	if err != nil {
		return ctrl.Result{}, err
	}

	resp, err := c.Write(ctx, path, s.GetIssuerAPIData())
	if err != nil {
		logger.Error(err, "Error issuing certificate from Vault")
		return ctrl.Result{}, err
	}

	if resp == nil {
		logger.Error(err, "Empty Vault secret", "path", path)
		return ctrl.Result{
			RequeueAfter: time.Second * 30,
		}, nil
	}

	certResp, err := vault.UnmarshalPKIIssueResponse(resp)
	if err != nil {
		return ctrl.Result{}, err
	}

	if certResp.SerialNumber == "" {
		logger.Error(
			fmt.Errorf("invalid secret data, serial_number cannot be empty"),
			"Error in Vault secret data")
		return ctrl.Result{}, err
	}

	data, err := vault.MarshalSecretData(resp)
	if err != nil {
		logger.Error(err, "Error marshalling Vault secret data")
		return ctrl.Result{}, err
	}
	if err := helpers.SyncSecret(ctx, r.Client, s, data); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Successfully updated the secret")

	// revoke the certificate on renewal
	if s.Spec.Revoke && s.Status.Renew && s.Status.SerialNumber != "" {
		if err := r.revokeCertificate(ctx, logger, s); err != nil {
			return ctrl.Result{}, err
		}
	}

	s.Status.SerialNumber = certResp.SerialNumber
	s.Status.Expiration = certResp.Expiration
	s.Status.Renew = false
	if err := r.Status().Update(ctx, s); err != nil {
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

func checkPKICertExpiry(expiration int64, offset time.Duration) bool {
	expiry := time.Unix(expiration-int64(offset.Seconds()), 0)
	now := time.Now()

	return now.After(expiry)
}
