// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
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

	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

const (
	instantUpdateErrorThreshold = 5
)

type websocketConnector interface {
	Connect(context.Context) (websocketConn, error)
}

type websocketConn interface {
	Read(context.Context) (websocket.MessageType, []byte, error)
	Close(websocket.StatusCode, string) error
}

type vaultWebsocketClientAdapter struct {
	client *vault.WebsocketClient
}

func (v vaultWebsocketClientAdapter) Connect(ctx context.Context) (websocketConn, error) {
	conn, err := v.client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return vaultWebsocketConnAdapter{conn: conn}, nil
}

type vaultWebsocketConnAdapter struct {
	conn *websocket.Conn
}

func (v vaultWebsocketConnAdapter) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	return v.conn.Read(ctx)
}

func (v vaultWebsocketConnAdapter) Close(code websocket.StatusCode, reason string) error {
	return v.conn.Close(code, reason)
}

// StreamSecretEventsFunc streams Vault events for the provided object.
type StreamSecretEventsFunc func(context.Context, client.Object, websocketConnector) error

// InstantUpdateConfig configures the behavior of EnsureInstantUpdateWatcher.
type InstantUpdateConfig struct {
	// VaultStaticSecret or VaultDynamicSecret to watch for instant updates.
	Secret client.Object
	// Client is the current Vault client tied to Object.
	Client vault.Client
	// WatchPath is passed to the Vault websocket client when starting a watch.
	WatchPath string
	// StreamSecretEvents handles websocket events and is invoked inside the watcher loop.
	StreamSecretEvents StreamSecretEventsFunc
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
	if ok {
		// The watcher is running, and if the VSS/VDS object has not been updated,
		// and the client ID is the same, just return
		if meta.LastGeneration == cfg.Secret.GetGeneration() && meta.LastClientID == cfg.Client.ID() {
			logger.V(consts.LogLevelDebug).Info("Event watcher already running",
				"namespace", cfg.Secret.GetNamespace(), "name", cfg.Secret.GetName())
			return nil
		}
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

	// connect to the Vault websocket server
	wsClient, err := cfg.Client.WebsocketClient(cfg.WatchPath)
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}
	wsAdapter := vaultWebsocketClientAdapter{client: wsClient}

	watchCtx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)
	cfg.Registry.Register(name, &eventWatcherMeta{
		Cancel:         cancel,
		LastClientID:   cfg.Client.ID(),
		LastGeneration: cfg.Secret.GetGeneration(),
		StoppedCh:      stoppedCh,
	})

	// Pass a deep copy of the VSS/VDS object here because it seems to avoid an issue
	// where the EventWatcherStarted event is occasionally emitted without a
	// name or namespace attached
	objCopy := cfg.Secret.DeepCopyObject()
	obj, ok := objCopy.(client.Object)
	if !ok {
		return fmt.Errorf("failed to convert object copy to client.Object: %T", objCopy)
	}

	// launch the goroutine to watch events
	go cfg.getEvents(watchCtx, name, obj, wsAdapter, stoppedCh)

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
func (cfg InstantUpdateConfig) getEvents(ctx context.Context, name types.NamespacedName, o client.Object, wsClient websocketConnector, stoppedCh chan struct{}) {
	logger := log.FromContext(ctx).WithName("getEvents")
	defer func() {
		cfg.Registry.Delete(name)
		close(stoppedCh)
	}()

	// Use the same backoff options used for Vault reads in Reconcile()
	retryBackoff := backoff.NewExponentialBackOff(cfg.BackOffRegistry.opts...)

	shouldBackoff := false
	errorCount := 0

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

			// handle secret updates based on events
			err := cfg.StreamSecretEvents(ctx, o, wsClient)
			if err == nil {
				shouldBackoff = false
				errorCount = 0
				retryBackoff.Reset()
				continue
			}

			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "context canceled") {
				// The connection and/or context was closed, so we should
				// exit the goroutine (and the defer will remove this from
				// the registry)
				logger.V(consts.LogLevelDebug).Info(
					"Websocket client closed, stopping GetEvents for",
					"namespace", o.GetNamespace(), "name", o.GetName())
				return
			}

			errorCount++
			shouldBackoff = true

			// For any other errors, we emit the error as an event on the
			// VSS/VDS, reload the client and try connecting again.
			cfg.Recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonEventWatcherError,
				"Error while watching events: %s", err)

			if errorCount >= instantUpdateErrorThreshold {
				logger.Error(err, "Too many errors while watching events, requeuing")
				cfg.enqueueForReconcile(name)
				return
			}

			newClient, clientErr := cfg.NewClientFunc(ctx, o)
			if clientErr != nil {
				logger.Error(clientErr, "Failed to retrieve Vault client")
				cfg.enqueueForReconcile(name)
				return
			}

			newWSClient, clientErr := newClient.WebsocketClient(cfg.WatchPath)
			if clientErr != nil {
				logger.Error(clientErr, "Failed to create new websocket client")
				cfg.enqueueForReconcile(name)
				return
			}
			wsClient = vaultWebsocketClientAdapter{client: newWSClient}

			// Update the LastClientID in the event registry
			meta, ok := cfg.Registry.Get(name)
			if !ok {
				logger.Error(fmt.Errorf("failed to get event watcher metadata"), "missing metadata", "object", name)
				cfg.enqueueForReconcile(name)
				return
			}

			meta.LastClientID = newClient.ID()
			cfg.Registry.Register(name, meta)
		}
	}
}

// enqueueForReconcile enqueues an object for reconciliation
func (cfg InstantUpdateConfig) enqueueForReconcile(key types.NamespacedName) {
	if cfg.SourceCh == nil || cfg.EventObjectFactory == nil {
		return
	}
	cfg.SourceCh <- event.GenericEvent{
		Object: cfg.EventObjectFactory(key),
	}
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

func (cfg *InstantUpdateConfig) validate() error {
	if cfg.Secret == nil {
		return fmt.Errorf("instant update watcher requires a non-nil object")
	}
	if cfg.Client == nil {
		return fmt.Errorf("instant update watcher requires a Vault client")
	}
	if cfg.WatchPath == "" {
		return fmt.Errorf("instant update watcher requires a watch path")
	}
	if cfg.StreamSecretEvents == nil {
		return fmt.Errorf("instant update watcher requires a stream function")
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
