// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

const (
	vaultTokenSecretFinalizer = "vaulttokensecret.secrets.hashicorp.com/finalizer"
)

// VaultTokenSecretReconciler reconciles a VaultTokenSecret object
type VaultTokenSecretReconciler struct {
	client.Client
	Scheme                      *runtime.Scheme
	Recorder                    record.EventRecorder
	ClientFactory               vault.ClientFactory
	SecretDataBuilder           *helpers.SecretDataBuilder
	SecretsClient               client.Client
	HMACValidator               helpers.HMACValidator
	referenceCache              ResourceReferenceCache
	GlobalTransformationOptions *helpers.GlobalTransformationOptions
	BackOffRegistry             *BackOffRegistry
	// SourceCh is used to trigger a requeue of resource instances from an
	// external source. Should be set on a source.Channel in SetupWithManager.
	// This channel should be closed when the controller is stopped.
	SourceCh             chan event.GenericEvent
	eventWatcherRegistry *eventWatcherRegistry
}

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttokensecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttokensecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaulttokensecrets/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultTokenSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *VaultTokenSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.VaultTokenSecret{}
	if err := r.Client.Get(ctx, req.NamespacedName, o); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		logger.Error(err, "error getting resource from k8s", "secret", o)
		return ctrl.Result{}, err
	}

	if o.GetDeletionTimestamp() != nil {
		logger.Info("Got deletion timestamp", "obj", o)
		return ctrl.Result{}, r.handleDeletion(ctx, o)
	}

	c, err := r.ClientFactory.Get(ctx, r.Client, o)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientConfigError,
			"Failed to get Vault auth login: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	var requeueAfter time.Duration
	if o.Spec.RefreshAfter != "" {
		d, err := parseDurationString(o.Spec.RefreshAfter, ".spec.refreshAfter", 0)
		if err != nil {
			logger.Error(err, "Field validation failed")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Field validation failed, err=%s", err)
			return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
		}
		requeueAfter = computeHorizonWithJitter(d)
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOptions)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	tokenReq, err := newTokenRequest(o.Spec)
	if err != nil {
		r.Recorder.Event(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret, err.Error())
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	resp, err := c.Write(ctx, tokenReq)
	if err != nil {
		if vault.IsForbiddenError(err) {
			c.Taint()
		}

		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to create Vault token: %s", err)
		return ctrl.Result{RequeueAfter: entry.NextBackOff()}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	authdata := make(map[string]any)

	if resp.Secret().Auth != nil {
		o.Status.TokenAccessor = resp.Secret().Auth.Accessor
		o.Status.EntityID = resp.Secret().Auth.EntityID
		o.Status.LeaseDuration = resp.Secret().Auth.LeaseDuration
		o.Status.LastRenewalTime = nowFunc().Unix()

		authdata["accessor"] = resp.Secret().Auth.Accessor
		authdata["token"] = resp.Secret().Auth.ClientToken
		authdata["policies"] = resp.Secret().Auth.Policies
		authdata["token_policies"] = resp.Secret().Auth.TokenPolicies
		authdata["identity_policies"] = resp.Secret().Auth.IdentityPolicies
		authdata["metadata"] = resp.Secret().Auth.Metadata
		authdata["entity_id"] = resp.Secret().Auth.EntityID
		authdata["orphan"] = resp.Secret().Auth.Orphan
		authdata["lease_duration"] = resp.Secret().Auth.LeaseDuration
		authdata["renewable"] = resp.Secret().Auth.Renewable
	}
	authinfo := make(map[string]any)
	authinfo["data"] = authdata

	data, err := r.SecretDataBuilder.WithVaultData(authdata, resp.Secret().Data, transOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretDataBuilderError,
			"Failed to build K8s secret data: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}
	leaseDuration := time.Duration(o.Status.LeaseDuration) * time.Second
	if leaseDuration < 1 {
		// set an artificial leaseDuration in the case the lease duration is not
		// compatible with computeHorizonWithJitter()
		leaseDuration = time.Second * 5
	}
	// leaseDuration = time.Second * 5

	horizon := computeDynamicHorizonWithJitter(leaseDuration, o.Spec.RenewalPercent)
	// if horizon > requeueAfter {
	requeueAfter = horizon
	// }
	r.Recorder.Eventf(o, corev1.EventTypeNormal, "requeueAfter", "requeueAfter: %d", requeueAfter)

	var doRolloutRestart bool
	doSync := true

	if doSync {
		if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
				"Failed to update k8s secret: %s", err)
			return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
		}
		reason := consts.ReasonSecretSynced
		if doRolloutRestart {
			reason = consts.ReasonSecretRotated
			// rollout-restart errors are not retryable
			// all error reporting is handled by helpers.HandleRolloutRestarts
			_ = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder)
		}
		r.Recorder.Event(o, corev1.EventTypeNormal, reason, "Secret synced")
	} else {
		logger.V(consts.LogLevelDebug).Info("Secret sync not required")
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultTokenSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = newResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}
	r.SourceCh = make(chan event.GenericEvent)
	r.eventWatcherRegistry = newEventWatcherRegistry()

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultTokenSecret{}).
		WithEventFilter(syncableSecretPredicate(nil)).
		WithOptions(opts).
		Watches(
			&secretsv1beta1.SecretTransformation{},
			NewEnqueueRefRequestsHandlerST(r.referenceCache, nil),
		).
		// In order to reduce the operator's memory usage, we only watch for the
		// Secret's metadata. That is sufficient for us to know when a Secret is
		// deleted. If we ever need to access to the Secret's data, we can always fetch
		// it from the API server in a RequestHandler, selectively based on the Secret's
		// labels.
		WatchesMetadata(
			&corev1.Secret{},
			&enqueueOnDeletionRequestHandler{
				gvk: secretsv1beta1.GroupVersion.WithKind(VaultTokenSecret.String()),
			},
			builder.WithPredicates(&secretsPredicate{}),
		).
		WatchesRawSource(
			source.Channel(r.SourceCh,
				&enqueueDelayingSyncEventHandler{
					enqueueDurationForJitter: time.Second * 2,
				},
			),
		).
		Complete(r)
}

func (r *VaultTokenSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultTokenSecret) error {
	logger := log.FromContext(ctx)
	logger.V(consts.LogLevelDebug).Info("Updating status")
	o.Status.LastGeneration = o.GetGeneration()
	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultTokenSecretFinalizer)
	return err
}

func (r *VaultTokenSecretReconciler) handleDeletion(ctx context.Context, o client.Object) error {
	logger := log.FromContext(ctx)
	logger.Info("deleting")

	objKey := client.ObjectKeyFromObject(o)
	r.referenceCache.Remove(SecretTransformation, objKey)
	r.BackOffRegistry.Delete(objKey)
	if controllerutil.ContainsFinalizer(o, vaultTokenSecretFinalizer) {
		logger.Info("Removing finalizer")
		if controllerutil.RemoveFinalizer(o, vaultTokenSecretFinalizer) {
			if err := r.Update(ctx, o); err != nil {
				logger.Error(err, "Failed to remove the finalizer")
				return err
			}
			logger.Info("Successfully removed the finalizer")
		}
	}
	return nil
}

func newTokenRequest(s secretsv1beta1.VaultTokenSecretSpec) (vault.WriteRequest, error) {
	var Req vault.WriteRequest
	Path := "auth/token/create"
	if s.TokenRole != "" {
		Path = Path + "/" + s.TokenRole
	}
	params := make(map[string]any)
	params["renewable"] = false
	params["no_default_policy"] = s.No_default_policy
	if s.TTL != "" {
		params["ttl"] = s.TTL
		params["explicit_max_ttl"] = s.TTL
	}
	if s.DisplayName != "" {
		params["display_name"] = s.DisplayName
	}
	if s.EntityAlias != "" {
		params["entity_alias"] = s.EntityAlias
	}
	if s.Policies != nil {
		params["policies"] = s.Policies
	}
	if s.Meta != nil {
		params["meta"] = s.Meta
	}

	Req = vault.NewWriteRequest(Path, params)

	return Req, nil
}
