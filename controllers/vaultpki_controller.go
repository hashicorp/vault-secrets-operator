/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultPKIFinalizer = "vaultpkis.secrets.hashicorp.com/finalizer"

// VaultPKIReconciler reconciles a VaultPKI object
type VaultPKIReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkis,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkis/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultpkis/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultPKI object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *VaultPKIReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	s := &secretsv1alpha1.VaultPKI{}
	if err := r.Client.Get(ctx, req.NamespacedName, s); err != nil {
		if apierrors.IsNotFound(err) {
			// logger.Info(fmt.Sprintf("Request not found %#v", req))
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", s)
		return ctrl.Result{}, err
	}

	path := r.getPath(s.Spec)
	logger = logger.WithValues("vault_path", path, "dest", s.Spec.Dest)

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
	sec, err := r.getSecret(ctx, logger, s)
	if err != nil {
		return ctrl.Result{
			RequeueAfter: time.Second * 10,
		}, err
	}

	c, err := r.getVaultClient(logger, s.Spec)
	if err != nil {
		return ctrl.Result{}, err
	}

	resp, err := c.Logical().WriteWithContext(ctx, path, s.GetIssuerAPIData())
	if err != nil {
		logger.Error(err, "Error issuing certificate from Vault")
		return ctrl.Result{}, err
	}

	if resp == nil {
		logger.Error(err, "Empty Vault secret", "path", path)
		return ctrl.Result{
			RequeueAfter: time.Second * 30,
		}, err
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

func (r *VaultPKIReconciler) handleDeletion(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) error {
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

func (r *VaultPKIReconciler) addFinalizer(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) error {
	if !controllerutil.ContainsFinalizer(s, vaultPKIFinalizer) {
		controllerutil.AddFinalizer(s, vaultPKIFinalizer)
		if err := r.Client.Update(ctx, s); err != nil {
			l.Error(err, "error updating VaultPKI resource")
			return err
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultPKIReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultPKI{}).
		Complete(r)
}

func (r *VaultPKIReconciler) finalizePKI(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) error {
	l.Info("Finalizing VaultPKI")
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

func (r *VaultPKIReconciler) getSecret(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) (*corev1.Secret, error) {
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

func (r *VaultPKIReconciler) clearSecretData(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) error {
	l.Info("Clearing the secret's data", "name", s.Spec.Dest)
	sec, err := r.getSecret(ctx, l, s)
	if err != nil {
		return err
	}

	sec.Data = nil

	return r.Client.Update(ctx, sec)
}

func (r *VaultPKIReconciler) revokeCertificate(ctx context.Context, l logr.Logger, s *secretsv1alpha1.VaultPKI) error {
	c, err := r.getVaultClient(l, s.Spec)
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

// TODO: duplicated in VaultSecretReconciler
func (r *VaultPKIReconciler) getVaultClient(l logr.Logger, spec secretsv1alpha1.VaultPKISpec) (*api.Client, error) {
	config := api.DefaultConfig()
	// TODO: get this from config, probably from env var VAULT_ADDR=http://vault.demo.svc.cluster.local:8200
	config.Address = "http://vault.demo.svc.cluster.local:8200"
	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	// TODO: get this from the service account, setup k8s-auth
	c.SetToken("root")

	// l.Info(fmt.Sprintf("Getting Vault client, ns=%q", spec.Namespace))
	if spec.Namespace != "" {
		c.SetNamespace(spec.Namespace)
	}

	return c, nil
}

func (r *VaultPKIReconciler) getPath(spec secretsv1alpha1.VaultPKISpec) string {
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

/*
: "VaultPKI", "vaultPKI": {"name":"vaultpki-sample-tenant-1","namespace":"tenant-1"}, "namespace": "tenant-1", "name": "vaultpki-sample-tenant-1", "reconcileID": "f899f51b-766c-410c-9235-0fd1b245099c"}
1.6601028624699044e+09  ERROR   failed to remove finalizer      {"controller": "vaultpki", "controllerGroup": "secrets.hashicorp.com", "controllerKind": "VaultPKI", "vaultPKI": {"name":"vaultpki-sample-tenant-1","namespace":"tenant-1"}, "namespace": "tenant-1", "name": "vaultpki-sample-tenant-1", "reconcileID": "f899f51b-766c-410c-9235-0fd1b245099c", "error": "client rate limiter Wait returned an error: context canceled"}
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).Reconcile
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:121
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).reconcileHandler
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:320
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).processNextWorkItem
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:273
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).Start.func2.2
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:234
1.6601028624704008e+09  ERROR   Reconciler error        {"controller": "vaultpki", "controllerGroup": "secrets.hashicorp.com", "controllerKind": "VaultPKI", "vaultPKI": {"name":"vaultpki-sample-tenant-1","namespace":"tenant-1"}, "namespace": "tenant-1", "name": "vaultpki-sample-tenant-1", "reconcileID": "f899f51b-766c-410c-9235-0fd1b245099c", "error": "client rate limiter Wait returned an error: context canceled"}
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).processNextWorkItem
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:273
sigs.k8s.io/controller-runtime/pkg/internal/controller.(*Controller).Start.func2.2
        /go/pkg/mod/sigs.k8s.io/controller-runtime@v0.12.3/pkg/internal/controller/controller.go:234
1.660102862470549e+09   INFO    All workers finished    {"controller": "vaultpki", "controllerGroup": "secrets.hashicorp.com", "controllerKind": "VaultPKI"}

*/
