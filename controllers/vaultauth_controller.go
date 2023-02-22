// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const vaultAuthFinalizer = "vaultauth.secrets.hashicorp.com/finalizer"

// VaultAuthReconciler reconciles a VaultAuth object
type VaultAuthReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultauths/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=get;list;create;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the VaultAuth object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
func (r *VaultAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	o, err := common.GetVaultAuth(ctx, r.Client, req.NamespacedName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "Failed to get VaultAuth resource", "resource", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() == nil {
		if err := r.addFinalizer(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		logger.Info("Got deletion timestamp", "obj", o)
		return r.handleFinalizer(ctx, o)
	}

	// ensure that the vaultConnectionRef is set for any VaultAuth resource in the operator namespace.
	if o.Namespace == common.OperatorNamespace && o.Spec.VaultConnectionRef == "" {
		err := fmt.Errorf("vaultConnectionRef must be set on resources in the %q namespace", common.OperatorNamespace)
		msg := "Invalid resource"
		logger.Error(err, msg)
		o.Status.Valid = false
		o.Status.Error = err.Error()
		logger.Error(err, o.Status.Error)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	connName, err := common.GetConnectionNamespacedName(o)
	if err != nil {
		o.Status.Valid = false
		o.Status.Error = consts.ReasonInvalidResourceRef
		msg := "Invalid vaultConnectionRef"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	if _, err = common.GetVaultConnection(ctx, r.Client, connName); err != nil {
		o.Status.Valid = false
		if apierrors.IsNotFound(err) {
			o.Status.Error = consts.ReasonConnectionNotFound
		} else {
			o.Status.Error = consts.ReasonInvalidConnection
		}

		msg := "Failed getting the VaultConnection resource"
		logger.Error(err, msg)
		r.recordEvent(o, o.Status.Error, msg+": %s", err)
		if err := r.updateStatus(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	o.Status.Valid = true
	o.Status.Error = ""
	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	// evict old referent VaultClientCaches for all older generations of self.
	// this is a bit of a sledgehammer, not all updated attributes of VaultAuth
	// warrant eviction of a client cache entry, but this is a good start.
	opts := cacheEvictionOption{
		filterFunc: filterOldCacheRefsForAuth,
		matchingLabels: client.MatchingLabels{
			"vaultAuthRef":          o.GetName(),
			"vaultAuthRefNamespace": o.GetNamespace(),
		},
	}
	if _, err := evictClientCacheRefs(ctx, r.Client, o, r.Recorder, opts); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
			"Failed to evict referent VaultCacheClient resources: %s", err)
	}

	msg := "Successfully handled VaultAuth resource request"
	logger.Info(msg)
	r.recordEvent(o, consts.ReasonAccepted, msg)

	return ctrl.Result{}, nil
}

func (r *VaultAuthReconciler) evictClientCacheRefs(ctx context.Context, o *secretsv1alpha1.VaultAuth, doEvict cacheFilterFunc) ([]string, error) {
	caches := &secretsv1alpha1.VaultClientCacheList{}
	matchLabels := client.MatchingLabels{
		"vaultAuthRef":          o.Name,
		"vaultAuthRefNamespace": o.Namespace,
	}
	if err := r.Client.List(ctx, caches, matchLabels); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
			"Failed to list VaultCacheClient resources")
		return nil, err
	}

	var evicted []string
	var err error
	// this is a bit of a sledgehammer, not all updated attributes of VaultAuth warrant evicting a client cache entry,
	// but this is a good start at ensuring that all cached clients for an auth are properly updated on new VaultAuth generations.
	for _, item := range caches.Items {
		if doEvict(o, item) {
			dcObj := item.DeepCopy()
			if err := r.Client.Delete(ctx, dcObj); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				// requires go1.20+
				err = errors.Join(err)
				r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
					"Failed to delete %s, on change to %s", item, o)
				continue
			}
			evicted = append(evicted, client.ObjectKeyFromObject(dcObj).String())
		}
	}

	r.Recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonVaultClientCacheEviction,
		"Evicted %d referent VaultCacheClient resources: %v", len(evicted), evicted)

	return evicted, err
}

func (r *VaultAuthReconciler) recordEvent(a *secretsv1alpha1.VaultAuth, reason, msg string, i ...interface{}) {
	eventType := corev1.EventTypeNormal
	if !a.Status.Valid {
		eventType = corev1.EventTypeWarning
	}

	r.Recorder.Eventf(a, eventType, reason, msg, i...)
}

func (r *VaultAuthReconciler) updateStatus(ctx context.Context, a *secretsv1alpha1.VaultAuth) error {
	logger := log.FromContext(ctx)
	// logger.Info("Updating status", "status", a.Status)
	metrics.SetResourceStatus("vaultauth", a, a.Status.Valid)
	if err := r.Status().Update(ctx, a); err != nil {
		msg := "Failed to update the resource's status"
		r.recordEvent(a, consts.ReasonStatusUpdateError, "%s: %s", msg, err)
		logger.Error(err, msg)
		return err
	}
	return nil
}

func (r *VaultAuthReconciler) addFinalizer(ctx context.Context, o *secretsv1alpha1.VaultAuth) error {
	if !controllerutil.ContainsFinalizer(o, vaultAuthFinalizer) {
		controllerutil.AddFinalizer(o, vaultAuthFinalizer)
		if err := r.Client.Update(ctx, o); err != nil {
			return err
		}
	}

	return nil
}

func (r *VaultAuthReconciler) handleFinalizer(ctx context.Context, o *secretsv1alpha1.VaultAuth) (ctrl.Result, error) {
	if controllerutil.ContainsFinalizer(o, vaultAuthFinalizer) {
		opts := cacheEvictionOption{
			filterFunc: filterAllCacheRefs,
			matchingLabels: client.MatchingLabels{
				"vaultAuthRef":          o.GetName(),
				"vaultAuthRefNamespace": o.GetNamespace(),
			},
		}
		_, err := evictClientCacheRefs(ctx, r.Client, o, r.Recorder, opts)
		if err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
				"Failed to evict referent VaultCacheClient resources: %s", err)
			return ctrl.Result{}, err
		}

		controllerutil.RemoveFinalizer(o, vaultAuthFinalizer)
		if err := r.Update(ctx, o); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.VaultAuth{}).
		Complete(r)
}
