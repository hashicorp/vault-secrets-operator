// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	vaultStaticSecretFinalizer = "vaultstaticsecret.secrets.hashicorp.com/finalizer"
)

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
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

// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//
// required for rollout-restart
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
//

func (r *VaultStaticSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	o := &secretsv1beta1.VaultStaticSecret{}
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

		horizon := computeHorizonWithJitter(requeueDurationOnError)
		if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse,
			"Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	destExists, _ := helpers.CheckSecretExists(ctx, r.Client, o)
	if !o.Spec.Destination.Create && !destExists {
		logger.Info("Destination secret does not exist, either create it or "+
			"set .spec.destination.create=true", "destination", o.Spec.Destination)
		return ctrl.Result{RequeueAfter: requeueDurationOnError}, nil
	}

	// we can ignore the error here, since it was handled above in the Get() call.
	clientCacheKey, _ := c.GetCacheKey()

	// update the VaultClientMeta in the resource's status.
	o.Status.VaultClientMeta.CacheKey = clientCacheKey.String()
	o.Status.VaultClientMeta.ID = c.ID()

	var requeueAfter time.Duration
	if o.Spec.RefreshAfter != "" {
		d, err := parseDurationString(o.Spec.RefreshAfter, ".spec.refreshAfter", 0)
		if err != nil {
			logger.Error(err, "Field validation failed")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Field validation failed, err=%s", err)

			horizon := computeHorizonWithJitter(requeueDurationOnError)
			if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse,
				"Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{
				RequeueAfter: horizon,
			}, nil
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

		horizon := computeHorizonWithJitter(requeueDurationOnError)
		if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	kvReq, err := newKVRequest(o.Spec)
	if err != nil {
		horizon := computeHorizonWithJitter(requeueDurationOnError)
		r.Recorder.Event(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret, err.Error())
		if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	resp, err := c.Read(ctx, kvReq)
	if err != nil {
		if vault.IsForbiddenError(err) {
			c.Taint()
		}

		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to read Vault secret: %s", err)

		horizon := entry.NextBackOff()
		if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	data, err := r.SecretDataBuilder.WithVaultData(resp.Data(), resp.Secret().Data, nil, transOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretDataBuilderError,
			"Failed to build K8s secret data: %s", err)

		horizon := computeHorizonWithJitter(requeueDurationOnError)
		if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{
			RequeueAfter: horizon,
		}, nil
	}

	var doRolloutRestart bool
	doSync := true
	if o.Spec.HMACSecretData != nil && *o.Spec.HMACSecretData {
		// we want to ensure that requeueAfter is set so that we can perform the proper drift detection during each reconciliation.
		// setting up a watcher on the Secret is also possibility, but polling seems to be the simplest approach for now.
		if requeueAfter == 0 {
			// hardcoding a default horizon here, perhaps we will want to make this value public?
			requeueAfter = computeHorizonWithJitter(time.Second * 60)
		}

		// doRolloutRestart only if this is not the first time this secret has been synced
		doRolloutRestart = o.Status.SecretMAC != ""

		macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.SecretsClient, r.HMACValidator, o, data)
		if err != nil {
			horizon := computeHorizonWithJitter(requeueDurationOnError)
			if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{
				RequeueAfter: horizon,
			}, nil
		}

		// skip the next sync if the data has not changed since the last sync, and the
		// resource has not been updated.
		if o.Status.LastGeneration == o.GetGeneration() {
			doSync = !macsEqual
		}

		o.Status.SecretMAC = base64.StdEncoding.EncodeToString(messageMAC)
	} else if len(o.Spec.RolloutRestartTargets) > 0 {
		logger.V(consts.LogLevelWarning).Info("Ignoring RolloutRestartTargets",
			"hmacSecretData", o.Spec.HMACSecretData,
			"targets", o.Spec.RolloutRestartTargets)
	}

	var conditions []metav1.Condition
	reason := consts.ReasonSecretSynced
	if doSync {
		if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
				"Failed to update k8s secret: %s", err)
			return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
		}

		conditions = append(conditions,
			newSyncCondition(o, metav1.ConditionTrue,
				"Secret synced, horizon=%s", requeueAfter),
		)
		r.Recorder.Event(o, corev1.EventTypeNormal, reason, "Secret synced")

		if doRolloutRestart && len(o.Spec.RolloutRestartTargets) > 0 {
			reason = consts.ReasonSecretRotated
			// rollout-restart errors are not retryable
			// all error reporting is handled by helpers.HandleRolloutRestarts
			if err = helpers.HandleRolloutRestarts(ctx, r.Client, o, r.Recorder); err != nil {
				conditions = append(
					conditions,
					newConditionNow(o,
						consts.TypeRolloutRestart,
						consts.ReasonRolloutRestartTriggeredFailed,
						metav1.ConditionFalse,
						"Rollout restart trigger failed, err=%s",
						err),
				)
			} else {
				conditions = append(
					conditions,
					newConditionNow(o,
						consts.TypeRolloutRestart,
						consts.ReasonRolloutRestartTriggered,
						metav1.ConditionTrue, "Rollout restart triggered"),
				)
			}
		}
	} else {
		logger.V(consts.LogLevelDebug).Info("Secret sync not required")
	}

	o.Status.LastGeneration = o.GetGeneration()
	if err := r.updateStatus(ctx, o, true, conditions...); err != nil {
		return ctrl.Result{}, err
	}

	if o.Spec.SyncConfig != nil && o.Spec.SyncConfig.InstantUpdates {
		logger.V(consts.LogLevelDebug).Info("Event watcher enabled")
		// ensure event watcher is running
		if err := r.ensureEventWatcher(ctx, o, c); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError, "Failed to watch events: %s", err)
		}
	} else {
		// ensure event watcher is not running
		r.unWatchEvents(o, c)
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *VaultStaticSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, healthy bool, conditions ...metav1.Condition) error {
	logger := log.FromContext(ctx).WithName("updateStatus")
	logger.V(consts.LogLevelDebug).Info("Updating status")
	o.Status.LastGeneration = o.GetGeneration()
	n := updateConditions(o.Status.Conditions, append(conditions, newHealthyCondition(o, healthy, "VaultStaticSecret"), newReadyCondition(o, healthy, "VaultStaticSecret"))...)
	logger.V(consts.LogLevelDebug).Info("Updating status", "n", n, "o", o.Status.Conditions)
	o.Status.Conditions = n

	if err := r.Status().Update(ctx, o); err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonStatusUpdateError,
			"Failed to update the resource's status, err=%s", err)
	}

	_, err := maybeAddFinalizer(ctx, r.Client, o, vaultStaticSecretFinalizer)
	return err
}

func (r *VaultStaticSecretReconciler) handleDeletion(ctx context.Context, o client.Object) error {
	logger := log.FromContext(ctx)
	objKey := client.ObjectKeyFromObject(o)
	r.referenceCache.Remove(SecretTransformation, objKey)
	r.BackOffRegistry.Delete(objKey)

	vss := o.(*secretsv1beta1.VaultStaticSecret)
	// Try to get the client for a clean unsubscribe; if unavailable, just remove from registry
	c, err := r.ClientFactory.Get(ctx, r.Client, vss)
	if err != nil {
		logger.V(consts.LogLevelDebug).Info("Client unavailable during deletion, removing from registry only",
			"error", err)
		r.eventWatcherRegistry.Delete(objKey)
	} else {
		r.unWatchEvents(vss, c)
	}

	if controllerutil.ContainsFinalizer(o, vaultStaticSecretFinalizer) {
		logger.Info("Removing finalizer")
		if controllerutil.RemoveFinalizer(o, vaultStaticSecretFinalizer) {
			if err := r.Update(ctx, o); err != nil {
				logger.Error(err, "Failed to remove the finalizer")
				return err
			}
			logger.Info("Successfully removed the finalizer")
		}
	}
	return nil
}

func (r *VaultStaticSecretReconciler) ensureEventWatcher(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, c vault.Client) error {
	logger := log.FromContext(ctx).WithName("ensureEventWatcher")
	name := client.ObjectKeyFromObject(o)

	meta, ok := r.eventWatcherRegistry.Get(name)
	if ok {
		// The subscription is active, and if the VSS object has not been updated,
		// and the client ID is the same, just return
		if meta.LastGeneration == o.GetGeneration() && meta.LastClientID == c.ID() {
			logger.V(consts.LogLevelDebug).Info("Event subscription already active",
				"namespace", o.Namespace, "name", o.Name)
			return nil
		}
		// The subscription exists but metadata or vault client has changed, unsubscribe first
		logger.V(consts.LogLevelDebug).Info("Unsubscribing due to metadata or client change",
			"namespace", o.Namespace, "name", o.Name)
		r.unWatchEvents(o, c)
	}

	// Build the vault path for subscription
	vaultPath := buildVaultEventPath(o)

	// Subscribe to events using the vault client
	subscriber := &vault.Subscriber{
		ResourceKey:  name,
		VaultNS:      o.Spec.Namespace,
		VaultPath:    vaultPath,
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  r.SourceCh,
	}

	if err := c.SubscribeToEvents(ctx, vault.EventTypeKV, subscriber); err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}

	// Update registry with new metadata
	updatedMeta := &eventWatcherMeta{
		LastClientID:   c.ID(),
		LastGeneration: o.GetGeneration(),
	}
	r.eventWatcherRegistry.Register(name, updatedMeta)

	logger.V(consts.LogLevelDebug).Info("Event subscription active", "meta", updatedMeta)
	r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonEventWatcherStarted, "Started watching events")

	return nil
}

// unWatchEvents unsubscribes the VSS from events and removes it from the registry
func (r *VaultStaticSecretReconciler) unWatchEvents(o *secretsv1beta1.VaultStaticSecret, c vault.Client) {
	name := client.ObjectKeyFromObject(o)
	_, ok := r.eventWatcherRegistry.Get(name)
	if !ok {
		return
	}

	vaultPath := buildVaultEventPath(o)
	pathKey := vault.SubscriptionKey{
		VaultNamespace: o.Spec.Namespace,
		VaultPath:      vaultPath,
	}

	if err := c.UnsubscribeFromEvents(vault.EventTypeKV, pathKey, name.String()); err != nil {
		log.FromContext(context.Background()).V(consts.LogLevelDebug).Info(
			"Failed to unsubscribe from events (may already be cleaned up)",
			"namespace", o.Namespace, "name", o.Name, "error", err)
	}

	r.eventWatcherRegistry.Delete(name)
}

// buildVaultEventPath constructs the Vault event path for a VaultStaticSecret.
// For KV v2, Vault emits events with the API path including /data/.
func buildVaultEventPath(o *secretsv1beta1.VaultStaticSecret) string {
	if o.Spec.Type == consts.KVSecretTypeV2 {
		return strings.Join([]string{o.Spec.Mount, "data", o.Spec.Path}, "/")
	}
	return strings.Join([]string{o.Spec.Mount, o.Spec.Path}, "/")
}

func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = NewResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}

	r.ClientFactory.RegisterClientCallbackHandler(
		vault.ClientCallbackHandler{
			On:       vault.ClientCallbackOnLifetimeWatcherDone | vault.ClientCallbackOnCacheRemoval,
			Callback: r.vaultClientCallback,
		},
	)

	r.SourceCh = make(chan event.GenericEvent)
	r.eventWatcherRegistry = newEventWatcherRegistry()

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1beta1.VaultStaticSecret{}).
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
				gvk: secretsv1beta1.GroupVersion.WithKind(VaultStaticSecret.String()),
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

// vaultClientCallback requests reconciliation of all VaultStaticSecret
// instances that were synced with Client
func (r *VaultStaticSecretReconciler) vaultClientCallback(ctx context.Context, c vault.Client) {
	logger := log.FromContext(ctx).WithName("vaultClientCallback")

	cacheKey, err := c.GetCacheKey()
	if err != nil {
		// should never get here
		logger.Error(err, "Invalid cache key, skipping syncing of VaultStaticSecret instances")
		return
	}

	logger = logger.WithValues("cacheKey", cacheKey, "controller", "vss")
	var l secretsv1beta1.VaultStaticSecretList
	if err := r.Client.List(ctx, &l, client.InNamespace(
		c.GetCredentialProvider().GetNamespace()),
	); err != nil {
		logger.Error(err, "Failed to list VaultStaticSecret instances")
		return
	}

	if len(l.Items) == 0 {
		return
	}

	reqs := map[client.ObjectKey]empty{}
	for _, o := range l.Items {
		if o.Status.VaultClientMeta.CacheKey == "" {
			logger.V(consts.LogLevelWarning).Info("Skipping, cacheKey is empty",
				"object", client.ObjectKeyFromObject(&o))
			continue
		}

		curCacheKey := vault.ClientCacheKey(o.Status.VaultClientMeta.CacheKey)
		if ok, err := curCacheKey.SameParent(cacheKey); ok {
			evt := event.GenericEvent{
				Object: &secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: o.GetNamespace(),
						Name:      o.GetName(),
					},
				},
			}

			objKey := client.ObjectKeyFromObject(evt.Object)
			if _, ok := reqs[objKey]; !ok {
				// deduplicating is probably not necessary, but we do it just in case.
				reqs[objKey] = empty{}
				logger.V(consts.LogLevelDebug).Info("Enqueuing VaultStaticSecret instance",
					"objKey", objKey)
				logger.V(consts.LogLevelDebug).Info(
					"Sending GenericEvent to the SourceCh", "evt", evt)
				r.SourceCh <- evt
			}
		} else if err != nil {
			logger.V(consts.LogLevelWarning).Info(
				"Skipping, cacheKey error", "error", err)
		}
	}
}

func newKVRequest(s secretsv1beta1.VaultStaticSecretSpec) (vault.ReadRequest, error) {
	var kvReq vault.ReadRequest
	switch s.Type {
	case consts.KVSecretTypeV1:
		kvReq = vault.NewKVReadRequestV1(s.Mount, s.Path, nil)
	case consts.KVSecretTypeV2:
		kvReq = vault.NewKVReadRequestV2(s.Mount, s.Path, s.Version, nil)
	default:
		return nil, fmt.Errorf("unsupported secret type %q", s.Type)
	}
	return kvReq, nil
}
