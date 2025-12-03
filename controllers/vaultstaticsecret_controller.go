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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"nhooyr.io/websocket"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/go-secure-stdlib/parseutil"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"

	"github.com/hashicorp/vault-secrets-operator/vault"
)

const (
	vaultStaticSecretFinalizer = "vaultstaticsecret.secrets.hashicorp.com/finalizer"
	kvEventPath                = "/v1/sys/events/subscribe/kv*"
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

			horizon := computeHorizonWithJitter(requeueDurationOnError)
			if err := r.updateStatus(ctx, o, false, newSyncCondition(o, metav1.ConditionFalse, "Failed to sync the secret, horizon=%s, err=%s", horizon, err)); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{
				RequeueAfter: horizon,
			}, nil
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

	if o.Spec.SyncConfig != nil && o.Spec.SyncConfig.InstantUpdates {
		logger.V(consts.LogLevelDebug).Info("Event watcher enabled")

		err := EnsureEventWatcher(ctx, &InstantUpdateConfig{
			Secret:          o,
			Client:          c,
			WatchPath:       kvEventPath,
			Registry:        r.eventWatcherRegistry,
			BackOffRegistry: r.BackOffRegistry,
			SourceCh:        r.SourceCh,
			Recorder:        r.Recorder,
			EventObjectFactory: func(key k8stypes.NamespacedName) client.Object {
				return &secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: key.Namespace,
						Name:      key.Name,
					},
				}
			},
			StreamSecretEvents: func(watchCtx context.Context, obj client.Object, wsClient websocketConnector) error {
				vss, ok := obj.(*secretsv1beta1.VaultStaticSecret)
				if !ok {
					return fmt.Errorf("unexpected object type %T", obj)
				}
				return r.streamStaticSecretEvents(watchCtx, vss, wsClient)
			},
			NewClientFunc: func(watchCtx context.Context, obj client.Object) (vault.Client, error) {
				vss, ok := obj.(*secretsv1beta1.VaultStaticSecret)
				if !ok {
					return nil, fmt.Errorf("unexpected object type %T", obj)
				}
				return r.ClientFactory.Get(watchCtx, r.Client, vss)
			},
		})
		if err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError, "Failed to watch events: %s", err)
		}
	} else {
		UnwatchEvents(r.eventWatcherRegistry, o)
	}

	o.Status.LastGeneration = o.GetGeneration()
	if err := r.updateStatus(ctx, o, true, conditions...); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *VaultStaticSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, healthy bool, conditions ...metav1.Condition) error {
	logger := log.FromContext(ctx).WithName("updateStatus")
	logger.V(consts.LogLevelDebug).Info("Updating status")
	o.Status.LastGeneration = o.GetGeneration()
	n := updateConditions(o.Status.Conditions, append(conditions, newHealthyCondition(o, healthy, "VaultStaticSecret"))...)
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
	UnwatchEvents(r.eventWatcherRegistry, o)
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

// eventMsg is used to extract the relevant fields from an event message sent
// from Vault
type eventMsg struct {
	Data struct {
		Event struct {
			Metadata struct {
				Path     string `json:"path"`
				Modified string `json:"modified"`
			} `json:"metadata"`
		} `json:"event"`
		Namespace string `json:"namespace"`
	} `json:"data"`
}

func (r *VaultStaticSecretReconciler) streamStaticSecretEvents(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, wsClient websocketConnector) error {
	logger := log.FromContext(ctx).WithName("streamStaticSecretEvents")
	conn, err := wsClient.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to vault websocket: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "closing event watcher")

	// We made it past the initial websocket connection, so emit a "good" event
	// status
	r.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonEventWatcherStarted, "Started watching events")

	for {
		select {
		case <-ctx.Done():
			logger.V(consts.LogLevelDebug).Info("Context done, closing websocket",
				"namespace", o.Namespace, "name", o.Name)
			return nil
		default:
			msgType, message, err := conn.Read(ctx)
			if err != nil {
				return fmt.Errorf("failed to read from websocket: %w, message: %q",
					err, string(message))
			}
			messageMap := eventMsg{}
			err = json.Unmarshal(message, &messageMap)
			if err != nil {
				return fmt.Errorf("failed to unmarshal event message: %w", err)
			}
			logger.V(consts.LogLevelTrace).Info("Received message",
				"message type", msgType, "message", messageMap)

			modified, err := parseutil.ParseBool(messageMap.Data.Event.Metadata.Modified)
			if err != nil {
				return fmt.Errorf("failed to parse modified field: %w", err)
			}

			if modified {
				namespace := strings.Trim(messageMap.Data.Namespace, "/")
				path := messageMap.Data.Event.Metadata.Path
				specPath := strings.Join([]string{o.Spec.Mount, o.Spec.Path}, "/")

				if o.Spec.Type == consts.KVSecretTypeV2 {
					specPath = strings.Join([]string{o.Spec.Mount, "data", o.Spec.Path}, "/")
				}
				logger.V(consts.LogLevelTrace).Info("modified Event received from Vault",
					"namespace", namespace, "path", path, "spec.namespace", o.Spec.Namespace,
					"spec path", specPath)
				if namespace == o.Spec.Namespace && path == specPath {
					logger.V(consts.LogLevelDebug).Info("Event matches, sending requeue",
						"namespace", namespace, "path", path)
					r.SourceCh <- event.GenericEvent{
						Object: &secretsv1beta1.VaultStaticSecret{
							ObjectMeta: metav1.ObjectMeta{
								Namespace: o.Namespace,
								Name:      o.Name,
							},
						},
					}
				}
			} else {
				// This is an event we're not interested in, ignore it and
				// carry on.
				logger.V(consts.LogLevelTrace).Info("Non-modified event received from Vault, ignoring",
					"message", messageMap)
				continue
			}
		}
	}
}

func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = NewResourceReferenceCache()
	if r.BackOffRegistry == nil {
		r.BackOffRegistry = NewBackOffRegistry()
	}
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
