// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
	vclient "github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// VaultTransitReconciler reconciles a VaultTransit object
type VaultTransitReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttransits,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttransits/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttransits/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultTransit object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.13.0/pkg/reconcile
func (r *VaultTransitReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info("Handling request", "req", req)

	s := &secretsv1alpha1.VaultTransit{}
	if err := r.Client.Get(ctx, req.NamespacedName, s); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		l.Error(err, "error getting resource from k8s", "secret", s)
		return ctrl.Result{}, err
	}

	if err := r.validate(ctx, s); err != nil {
		s.Status.Valid = false
		s.Status.Error = err.Error()
	} else {
		s.Status.Valid = true
		s.Status.Error = ""
	}

	if err := r.updateStatus(ctx, s); err != nil {
		return ctrl.Result{}, err
	}

	if !s.Status.Valid {
		return ctrl.Result{
			RequeueAfter: computeHorizonWithJitter(time.Second * 5),
		}, nil
	}

	return ctrl.Result{}, nil
}

func (r *VaultTransitReconciler) updateStatus(ctx context.Context, o *secretsv1alpha1.VaultTransit) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("vaulttransit", o, o.Status.Valid)
	if err := r.Status().Update(ctx, o); err != nil {
		msg := "Failed to update the resource's status, err=%s"
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError, msg, err)
		logger.Error(err, msg)
		return err
	}
	return nil
}

func (r *VaultTransitReconciler) validate(ctx context.Context, s *secretsv1alpha1.VaultTransit) error {
	rb := make([]byte, 10)
	if _, err := rand.Read(rb); err != nil {
		// should never happen
		return err
	}

	b, err := vclient.EncryptWithTransitFromObj(ctx, r.Client, s, rb)
	if err != nil {
		return err
	}

	r.Recorder.Eventf(s, corev1.EventTypeNormal, consts.ReasonTransitEncryptSuccessful,
		"Successfully encrypted test token")

	d, err := vclient.DecryptWithTransitFromObj(ctx, r.Client, s, b)
	if err != nil {
		return err
	}

	r.Recorder.Eventf(s, corev1.EventTypeNormal, consts.ReasonTransitDecryptSuccessful,
		"Successfully decrypted test token")

	if !bytes.Equal(rb, d) {
		return fmt.Errorf("decrypted output does not match expected")
	}

	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultTransitReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultTransit{}).
		WithEventFilter(ignoreUpdatePredicate()).
		WithEventFilter(filterNamespacePredicate([]string{common.OperatorNamespace})).
		Complete(r)
}
