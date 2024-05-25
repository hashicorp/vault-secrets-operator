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
	"k8s.io/apimachinery/pkg/types"
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

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const vaultStaticSecretFinalizer = "vaultstaticsecret.secrets.hashicorp.com/finalizer"

// VaultStaticSecretReconciler reconciles a VaultStaticSecret object
type VaultStaticSecretReconciler struct {
	client.Client
	Scheme                     *runtime.Scheme
	Recorder                   record.EventRecorder
	ClientFactory              vault.ClientFactory
	SecretDataBuilder          *helpers.SecretDataBuilder
	HMACValidator              helpers.HMACValidator
	referenceCache             ResourceReferenceCache
	GlobalTransformationOption *helpers.GlobalTransformationOption
	BackOffRegistry            *BackOffRegistry
	// SourceCh is used to trigger a requeue of resource instances from an
	// external source. Should be set on a source.Channel in SetupWithManager.
	// This channel should be closed when the controller is stopped.
	SourceCh             chan event.GenericEvent
	eventWatcherRegistry *EventWatcherRegistry
}

//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hashicorp.com,resources=vaultstaticsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
//
// required for rollout-restart
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;patch
//+kubebuilder:rbac:groups=argoproj.io,resources=rollouts,verbs=get;list;watch;patch
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
		return ctrl.Result{}, err
	}

	var requeueAfter time.Duration
	if o.Spec.RefreshAfter != "" {
		d, err := parseDurationString(o.Spec.RefreshAfter, ".spec.refreshAfter", 0)
		if err != nil {
			logger.Error(err, "Field validation failed")
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret,
				"Field validation failed, err=%s", err)
			return ctrl.Result{}, err
		}
		requeueAfter = computeHorizonWithJitter(d)
	}

	r.referenceCache.Set(SecretTransformation, req.NamespacedName,
		helpers.GetTransformationRefObjKeys(
			o.Spec.Destination.Transformation, o.Namespace)...)

	transOption, err := helpers.NewSecretTransformationOption(ctx, r.Client, o, r.GlobalTransformationOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonTransformationError,
			"Failed setting up SecretTransformationOption: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
	}

	kvReq, err := newKVRequest(o.Spec)
	if err != nil {
		r.Recorder.Event(o, corev1.EventTypeWarning, consts.ReasonVaultStaticSecret, err.Error())
		return ctrl.Result{}, err
	}

	resp, err := c.Read(ctx, kvReq)
	if err != nil {
		entry, _ := r.BackOffRegistry.Get(req.NamespacedName)
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonVaultClientError,
			"Failed to read Vault secret: %s", err)
		return ctrl.Result{RequeueAfter: entry.NextBackOff()}, nil
	} else {
		r.BackOffRegistry.Delete(req.NamespacedName)
	}

	data, err := r.SecretDataBuilder.WithVaultData(resp.Data(), resp.Secret().Data, transOption)
	if err != nil {
		r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretDataBuilderError,
			"Failed to build K8s secret data: %s", err)
		return ctrl.Result{RequeueAfter: computeHorizonWithJitter(requeueDurationOnError)}, nil
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

		macsEqual, messageMAC, err := helpers.HandleSecretHMAC(ctx, r.Client, r.HMACValidator, o, data)
		if err != nil {
			return ctrl.Result{}, err
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

	if doSync {
		if err := helpers.SyncSecret(ctx, r.Client, o, data); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonSecretSyncError,
				"Failed to update k8s secret: %s", err)
			return ctrl.Result{}, err
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

	if o.Spec.TBDInstantUpdateEventFlag {
		logger.V(consts.LogLevelDebug).Info("Event watcher enabled")
		// ensure event watcher is running
		if err := r.watchEvents(ctx, o, c); err != nil {
			r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError, "Failed to watch events: %s", err)
		}
	} else {
		// ensure event watcher is not running
		r.unWatchEvents(o)
	}

	if err := r.updateStatus(ctx, o); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: requeueAfter,
	}, nil
}

func (r *VaultStaticSecretReconciler) updateStatus(ctx context.Context, o *secretsv1beta1.VaultStaticSecret) error {
	logger := log.FromContext(ctx)
	logger.V(consts.LogLevelDebug).Info("Updating status")
	o.Status.LastGeneration = o.GetGeneration()
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
	r.unWatchEvents(o.(*secretsv1beta1.VaultStaticSecret))
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

func (r *VaultStaticSecretReconciler) watchEvents(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, c vault.Client) error {
	logger := log.FromContext(ctx)
	name := types.NamespacedName{Namespace: o.Namespace, Name: o.Name}

	meta, ok := r.eventWatcherRegistry.Get(name)
	if ok {
		// the watcher is running, so check if secret metadata has changed
		if meta.Namespace == o.Spec.Namespace && meta.Path == o.Spec.Path && meta.Type == o.Spec.Type {
			return nil
		}
	}
	if meta != nil {
		// the watcher is running, but the metadata has changed, so close it
		if meta.Cancel != nil {
			meta.Cancel()
		} else {
			logger.Error(fmt.Errorf("nil cancel function"), "event watcher has nil cancel function", "meta", meta)
		}
	}

	wsClient, err := c.WebsocketClient()
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	updatedMeta := &eventWatcherMeta{
		Cancel:    cancel,
		Namespace: o.Spec.Namespace,
		Type:      o.Spec.Type,
		Path:      o.Spec.Path,
	}
	// launch the goroutine to watch events
	logger.V(consts.LogLevelDebug).Info("Starting event watcher", "meta", updatedMeta)
	go r.GetEvents(watchCtx, o, wsClient)
	r.eventWatcherRegistry.Register(name, updatedMeta)

	return nil
}

// unWatchEvents - If the VSS is in the registry, cancel its event watcher
// context to close the goroutine and remove the VSS from the registry
func (r *VaultStaticSecretReconciler) unWatchEvents(o *secretsv1beta1.VaultStaticSecret) {
	name := types.NamespacedName{Namespace: o.Namespace, Name: o.Name}
	meta, ok := r.eventWatcherRegistry.Get(name)
	if ok {
		if meta.Cancel != nil {
			meta.Cancel()
		}
		r.eventWatcherRegistry.Delete(name)
	}
}

func (r *VaultStaticSecretReconciler) GetEvents(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, wsClient *vault.WebsocketClient) error {
	logger := log.FromContext(ctx)
	name := types.NamespacedName{Namespace: o.Namespace, Name: o.Name}
	defer r.eventWatcherRegistry.Delete(name)

	shouldBackoff := false
	requeue := false

eventLoop:
	for {
		select {
		case <-ctx.Done():
			logger.V(consts.LogLevelDebug).Info("Context done, stopping GetEvents for", "namespace", o.Namespace, "name", o.Name)
			return nil
		default:
			if shouldBackoff {
				time.Sleep(time.Second * 10)
			}
			err := r.streamStaticSecretEvents(ctx, o, wsClient)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "context canceled") {
					// the connection and/or context was closed, so we should
					// exit the goroutine (and the defer will remove this from
					// the registry)
					logger.V(consts.LogLevelDebug).Info("Websocket client closed, stopping GetEvents for", "namespace", o.Namespace, "name", o.Name)
					return nil
				}
				shouldBackoff = true

				// TODO(tvoran): if the error contains "permission denied" or
				// "invalid token", we should refresh the websocket client from
				// the appropriate cached vault client,
				if strings.Contains(err.Error(), "permission denied") {
					logger.Error(err, "Permission denied watching events")
					r.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError, "Permission denied watching events: %s", err)
					continue
				}

				if strings.Contains(err.Error(), "invalid token") {
					logger.Error(err, "Invalid token while watching events")
					newVaultClient, err := r.ClientFactory.Get(ctx, r.Client, o)
					if err != nil {
						requeue = true
						break eventLoop
					} else {
						wsClient, err = newVaultClient.WebsocketClient()
						if err != nil {
							logger.Error(err, "Failed to create new websocket client")
							requeue = true
							break eventLoop
						}
					}
				}

				logger.Error(err, "Error watching events")

				continue
			}
		}
	}

	if requeue {
		r.SourceCh <- event.GenericEvent{
			Object: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: o.Namespace,
					Name:      o.Name,
				},
			},
		}
	}
	return nil
}

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

func (r *VaultStaticSecretReconciler) streamStaticSecretEvents(ctx context.Context, o *secretsv1beta1.VaultStaticSecret, wsClient *vault.WebsocketClient) error {
	logger := log.FromContext(ctx)
	logger.V(consts.LogLevelDebug).Info("Starting to watch events for", "namespace", o.Namespace, "name", o.Name)
	conn, err := wsClient.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to vault websocket: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	for {
		select {
		case <-ctx.Done():
			logger.V(consts.LogLevelDebug).Info("Context done, closing websocket for", "namespace", o.Namespace, "name", o.Name)
			return nil
		default:
			msgType, message, err := conn.Read(ctx)
			if err != nil {
				return fmt.Errorf("failed to read from websocket: %w", err)
			}
			messageMap := eventMsg{}
			err = json.Unmarshal(message, &messageMap)
			if err != nil {
				return fmt.Errorf("failed to unmarshal event message: %w", err)
			}
			logger.V(consts.LogLevelDebug).Info("Received message", "message type", msgType, "message", messageMap)
			namespace := strings.Trim(messageMap.Data.Namespace, "/")
			path := messageMap.Data.Event.Metadata.Path
			modified := messageMap.Data.Event.Metadata.Modified

			if modified == "true" {
				specPath := strings.Join([]string{o.Spec.Mount, o.Spec.Path}, "/")
				if o.Spec.Type == consts.KVSecretTypeV2 {
					specPath = strings.Join([]string{o.Spec.Mount, "data", o.Spec.Path}, "/")
				}
				logger.V(consts.LogLevelDebug).Info("modified Event received from Vault", "namespace", namespace, "path", path, "spec.namespace", o.Spec.Namespace, "spec path", specPath)
				if namespace == o.Spec.Namespace && path == specPath {
					logger.V(consts.LogLevelDebug).Info("Event matches, sending requeue", "namespace", namespace, "path", path)
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
				continue
			}
		}
	}
}

func (r *VaultStaticSecretReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	r.referenceCache = newResourceReferenceCache()
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
		Watches(
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
		kvReq = vault.NewKVReadRequestV1(s.Mount, s.Path)
	case consts.KVSecretTypeV2:
		kvReq = vault.NewKVReadRequestV2(s.Mount, s.Path, s.Version)
	default:
		return nil, fmt.Errorf("unsupported secret type %q", s.Type)
	}
	return kvReq, nil
}
