// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"nhooyr.io/websocket"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

const (
	// InstantUpdateEventPath is the path to subscribe to Vault events
	InstantUpdateEventPath = "/v1/sys/events/subscribe/*"

	// InstantUpdateErrorThreshold is the number of consecutive errors before the watcher is restarted
	InstantUpdateErrorThreshold = 5
)

// InstantUpdateConfig configures the behavior of EnsureInstantUpdateWatcher.
type InstantUpdateConfig struct {
	// VaultStaticSecret or VaultDynamicSecret to watch for instant updates.
	Secret client.Object
	// Client is the current Vault client tied to Object.
	Client vault.Client
	// Registry tracks active event watchers.
	Registry *eventWatcherRegistry
	// BackOffRegistry provides retry intervals for reconnect attempts.
	BackOffRegistry *BackOffRegistry
	// SourceCh is used to enqueue the object for reconciliation.
	SourceCh chan event.GenericEvent
	// Recorder emits Kubernetes events for watcher errors.
	Recorder record.EventRecorder
	// NewClientFunc reloads a Vault client for Object when the websocket
	// stream encounters an error.
	NewClientFunc func(context.Context, client.Object) (vault.Client, error)
	// EventObjectFactory builds the object sent on SourceCh. When nil a default
	// factory that deep copies Object is used.
	EventObjectFactory func(types.NamespacedName) client.Object
}

// vaultEventMessage is used to extract the relevant fields from an event message sent from Vault.
type vaultEventMessage struct {
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

// EnsureEventWatcher starts (or restarts) the instant update watcher
// for the provided object. The caller is responsible for ensuring that the
// config fields are populated.
func EnsureEventWatcher(ctx context.Context, cfg *InstantUpdateConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}

	logger := log.FromContext(ctx).WithName("EnsureEventWatcher")
	name := client.ObjectKeyFromObject(cfg.Secret)

	meta, ok := cfg.Registry.Get(name)

	// The watcher is running, and if the VSS/VDS object has not been updated,
	// and the client ID is the same, just return
	if ok && meta.LastGeneration == cfg.Secret.GetGeneration() && meta.LastClientID == cfg.Client.ID() {
		logger.V(consts.LogLevelDebug).Info("Event watcher already running",
			"namespace", cfg.Secret.GetNamespace(), "name", cfg.Secret.GetName())
		return nil
	}

	if meta != nil {
		// The watcher is running, but the metadata or vault client has changed,
		// so kill it
		if meta.Cancel != nil {
			meta.Cancel()
			waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := waitForStoppedCh(waitCtx, meta.StoppedCh); err != nil {
				logger.Error(err, "Failed to stop event watcher", "object", name)
			}
		} else {
			logger.Error(fmt.Errorf("nil cancel function"), "event watcher has nil cancel function", "object", name)
		}
	}

	// create the websocket that will be used to receive instant update events
	wsClient, err := cfg.Client.WebsocketClient(InstantUpdateEventPath)
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}

	conn, err := wsClient.Connect(ctx)
	if err != nil {
		return err
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)
	updatedMeta := &eventWatcherMeta{
		Cancel:         cancel,
		LastClientID:   cfg.Client.ID(),
		LastGeneration: cfg.Secret.GetGeneration(),
		StoppedCh:      stoppedCh,
	}
	cfg.Registry.Register(name, updatedMeta)
	logger.V(consts.LogLevelDebug).Info("Starting event watcher", "meta", updatedMeta)

	// Pass a deep copy of the VSS/VDS object here because it seems to avoid an issue
	// where the EventWatcherStarted event is occasionally emitted without a
	// name or namespace attached
	objCopy := cfg.Secret.DeepCopyObject()
	obj, ok := objCopy.(client.Object)
	if !ok {
		return fmt.Errorf("failed to convert object copy to client.Object: %T", objCopy)
	}

	// launch the goroutine to watch events
	go cfg.getEvents(watchCtx, obj, conn, stoppedCh)

	return nil
}

// UnwatchEvents - If the VSS/VDS is in the registry, cancel its event watcher
// context to close the goroutine, and remove the VSS/VDS from the registry
func UnwatchEvents(registry *eventWatcherRegistry, obj client.Object) {
	if registry == nil || obj == nil {
		return
	}
	key := client.ObjectKeyFromObject(obj)
	meta, ok := registry.Get(key)
	if ok {
		if meta.Cancel != nil {
			meta.Cancel()
		}
		registry.Delete(key)
	}
}

// getEvents streams event notifications from Vault and handles errors and retries
func (cfg *InstantUpdateConfig) getEvents(ctx context.Context, o client.Object, conn *websocket.Conn, stoppedCh chan struct{}) {
	logger := log.FromContext(ctx).WithName("getEvents")
	name := client.ObjectKeyFromObject(o)
	defer func() {
		cfg.Registry.Delete(name)
		if conn != nil {
			conn.Close(websocket.StatusNormalClosure, "closing websocket watcher")
		}
		close(stoppedCh)
	}()

	// Use the same backoff options used for Vault reads in Reconcile()
	retryBackoff := backoff.NewExponentialBackOff(cfg.BackOffRegistry.opts...)

	shouldBackoff := false
	errorCount := 0

	cfg.Recorder.Event(o, corev1.EventTypeNormal, consts.ReasonEventWatcherStarted, "Started watching events")

	for {
		select {
		case <-ctx.Done():
			logger.V(consts.LogLevelDebug).Info("Context done, stopping watcher")
			return
		default:
			if shouldBackoff {
				nextBackoff := retryBackoff.NextBackOff()
				if nextBackoff == backoff.Stop {
					logger.Error(fmt.Errorf("backoff limit reached"), "Backoff limit reached, requeuing")
					cfg.enqueueForReconcile(name)
					return
				}
				time.Sleep(nextBackoff)
			}

			select {
			case <-ctx.Done():
				logger.V(consts.LogLevelDebug).Info("Context done, stopping watcher")
				return
			default:
				msgType, data, err := conn.Read(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}

					logger.Error(err, "Websocket watcher read failed", "object", name)
					cfg.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError,
						"Error while watching events: %s", err)
					errorCount++
					shouldBackoff = true

					if errorCount >= InstantUpdateErrorThreshold {
						logger.Error(err, "Too many errors while watching events, requeuing")
						cfg.enqueueForReconcile(name)
						return
					}

					// attempt to reconnect to the websocket upon error
					newClient, newConn, reconnectErr := cfg.reloadClientAndReconnect(ctx, o)
					if reconnectErr != nil {
						logger.Error(reconnectErr, "Failed to reconnect websocket watcher", "object", name)
						continue
					}
					if conn != nil {
						conn.Close(websocket.StatusNormalClosure, "closing websocket watcher")
					}

					conn = newConn
					cfg.Client = newClient
					if meta, ok := cfg.Registry.Get(name); ok {
						meta.LastClientID = newClient.ID()
					}

					shouldBackoff = false
					errorCount = 0
					retryBackoff.Reset()
					continue
				}

				matched := false
				matched, err = cfg.streamSecretEvents(ctx, o, msgType, data)
				if err == nil {
					if matched {
						cfg.enqueueForReconcile(name)
					}
					shouldBackoff = false
					errorCount = 0
					retryBackoff.Reset()
					continue
				}

				errorCount++
				shouldBackoff = true

				// For any other errors, we emit the error as an event on the
				// VSS/VDS and try again with backoff.
				cfg.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError,
					"Error while watching events: %s", err)

				if errorCount >= InstantUpdateErrorThreshold {
					logger.Error(err, "Too many errors while watching events, requeuing")
					cfg.enqueueForReconcile(name)
					return
				}
			}
		}
	}
}

func (cfg *InstantUpdateConfig) streamSecretEvents(ctx context.Context, obj client.Object, _ websocket.MessageType, data []byte) (bool, error) {
	logger := log.FromContext(ctx).WithName("streamSecretEvents")

	message := vaultEventMessage{}
	if err := json.Unmarshal(data, &message); err != nil {
		return false, fmt.Errorf("failed to unmarshal event message: %w", err)
	}

	if message.Data.Event.Metadata.Modified == "" {
		return false, nil
	}

	modified, err := strconv.ParseBool(message.Data.Event.Metadata.Modified)
	if err != nil {
		return false, fmt.Errorf("failed to parse modified field: %w", err)
	}
	if !modified {
		return false, nil
	}

	namespace := strings.Trim(message.Data.Namespace, "/")
	path := message.Data.Event.Metadata.Path

	var specNamespace string
	var specPath string

	switch o := obj.(type) {
	case *secretsv1beta1.VaultStaticSecret:
		specNamespace = strings.Trim(o.Spec.Namespace, "/")
		if o.Spec.Type == consts.KVSecretTypeV1 {
			specPath = strings.Join([]string{o.Spec.Mount, o.Spec.Path}, "/")
		} else {
			specPath = strings.Join([]string{o.Spec.Mount, "data", o.Spec.Path}, "/")
		}
	default:
		return false, fmt.Errorf("unexpected object type %T", obj)
	}

	if namespace != specNamespace || path != specPath {
		logger.V(consts.LogLevelDebug).Info("Event is not relevant for instant updates, skipping",
			"namespace", namespace, "path", path, "spec namespace", specNamespace, "spec path", specPath)
		return false, nil
	}

	logger.V(consts.LogLevelDebug).Info("Event matches, requeueing",
		"namespace", namespace, "path", path)
	return true, nil
}

// reloadClientAndReconnect reloads the vault client and reconnects to the websocket
func (cfg *InstantUpdateConfig) reloadClientAndReconnect(ctx context.Context, obj client.Object) (vault.Client, *websocket.Conn, error) {
	newClient, err := cfg.NewClientFunc(ctx, obj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to reload vault client: %w", err)
	}

	wsClient, err := newClient.WebsocketClient(InstantUpdateEventPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create websocket client: %w", err)
	}

	conn, err := wsClient.Connect(ctx)
	if err != nil {
		return nil, nil, err
	}

	return newClient, conn, nil
}

// enqueueForReconcile enqueues an object for reconciliation
func (cfg *InstantUpdateConfig) enqueueForReconcile(key types.NamespacedName) {
	if cfg.SourceCh == nil || cfg.EventObjectFactory == nil {
		return
	}
	cfg.SourceCh <- event.GenericEvent{
		Object: cfg.EventObjectFactory(key),
	}
}

func (cfg *InstantUpdateConfig) validate() error {
	if cfg.Secret == nil {
		return fmt.Errorf("instant update watcher requires a non-nil object")
	}
	if cfg.Client == nil {
		return fmt.Errorf("instant update watcher requires a Vault client")
	}
	if cfg.Registry == nil || cfg.BackOffRegistry == nil {
		return fmt.Errorf("instant update watcher requires registries")
	}
	if cfg.SourceCh == nil {
		return fmt.Errorf("instant update watcher requires a source channel")
	}
	if cfg.Recorder == nil {
		return fmt.Errorf("instant update watcher requires a recorder")
	}
	if cfg.NewClientFunc == nil {
		return fmt.Errorf("instant update watcher requires a client factory")
	}
	if cfg.EventObjectFactory == nil {
		cfg.EventObjectFactory = defaultEventObjectFactory(cfg.Secret)
	}
	return nil
}

// defaultEventObjectFactory creates a default event object factory for tests
func defaultEventObjectFactory(template client.Object) func(types.NamespacedName) client.Object {
	return func(key types.NamespacedName) client.Object {
		objCopy := template.DeepCopyObject()
		obj, ok := objCopy.(client.Object)
		if !ok {
			return template
		}
		obj.SetNamespace(key.Namespace)
		obj.SetName(key.Name)
		obj.SetResourceVersion("")
		return obj
	}
}
