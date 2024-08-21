// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

// HCPAuthReconciler reconciles a HCPAuth object
type HCPAuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpauths,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpauths/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=hcpauths/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile validates the HCPAuth CR instance, updating the instance's status
// with the result.
func (r *HCPAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.HCPAuth{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", o)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		metrics.DeleteResourceStatus("hcpauth", o)
		return ctrl.Result{}, nil
	}

	// perform a rudimentary health check on the HCP host on port 443.
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:443", hvsclient.DefaultHost), time.Second*5)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	var errs error
	if err != nil {
		err = fmt.Errorf("connection check failed, err=%w", err)
		logger.Error(err, "Validation failed")
		errs = errors.Join(err)
		o.Status.Error = err.Error()
		o.Status.Valid = ptr.To(true)
	} else {
		o.Status.Error = ""
		o.Status.Valid = ptr.To(true)
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, errors.Join(errs, err)
	}

	var requeueAfter time.Duration
	if errs != nil {
		requeueAfter = computeHorizonWithJitter(time.Second * 15)
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *HCPAuthReconciler) updateStatus(ctx context.Context, a *secretsv1beta1.HCPAuth) error {
	logger := log.FromContext(ctx)
	metrics.SetResourceStatus("hcpauth", a, ptr.Deref(a.Status.Valid, false))
	if err := r.Status().Update(ctx, a); err != nil {
		logger.Error(err, "Failed to update the resource's status")
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HCPAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.HCPAuth{}).
		Complete(r)
}
