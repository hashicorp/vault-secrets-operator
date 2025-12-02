// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

const instantUpdateErrorThreshold = 5

// InstantStreamFunc streams Vault events for the provided object.
type InstantStreamFunc func(context.Context, client.Object, *vault.WebsocketClient) error

// InstantUpdateConfig configures the behavior of EnsureInstantUpdateWatcher.
type InstantUpdateConfig struct {
	// Object to watch for instant updates.
	Object client.Object
	// Client is the current Vault client tied to Object.
	Client vault.Client
	// WatchPath is passed to the Vault websocket client when starting a watch.
	WatchPath string
	// Stream handles websocket events and is invoked inside the watcher loop.
	Stream InstantStreamFunc
	// Registry tracks active event watchers.
	Registry *eventWatcherRegistry
	// BackOffRegistry provides retry intervals for reconnect attempts.
	BackOffRegistry *BackOffRegistry
	// SourceCh is used to enqueue the object for reconciliation.
	SourceCh chan event.GenericEvent
	// Recorder emits Kubernetes events for watcher errors.
	Recorder record.EventRecorder
	// Logger is used for structured logging.
	Logger logr.Logger
	// NewClientFunc reloads a Vault client for Object when the websocket
	// stream encounters an error.
	NewClientFunc func(context.Context, client.Object) (vault.Client, error)
	// EventObjectFactory builds the object sent on SourceCh. When nil a default
	// factory that deep copies Object is used.
	EventObjectFactory func(types.NamespacedName) client.Object
}

// EnsureInstantUpdateWatcher starts (or restarts) the instant update watcher
// for the provided object. The caller is responsible for ensuring that the
// config fields are populated.
func EnsureInstantUpdateWatcher(ctx context.Context, cfg InstantUpdateConfig) error {
	if cfg.Object == nil {
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
	if cfg.Stream == nil {
		return fmt.Errorf("instant update watcher requires a stream function")
	}
	if cfg.NewClientFunc == nil {
		return fmt.Errorf("instant update watcher requires a client factory")
	}
	if cfg.WatchPath == "" {
		return fmt.Errorf("instant update watcher requires a watch path")
	}
	if cfg.EventObjectFactory == nil {
		cfg.EventObjectFactory = defaultEventObjectFactory(cfg.Object)
	}

	logger := cfg.Logger
	key := client.ObjectKeyFromObject(cfg.Object)

	meta, ok := cfg.Registry.Get(key)
	if ok {
		if meta.LastGeneration == cfg.Object.GetGeneration() && meta.LastClientID == cfg.Client.ID() {
			logger.V(consts.LogLevelDebug).Info("Event watcher already running",
				"namespace", cfg.Object.GetNamespace(), "name", cfg.Object.GetName())
			return nil
		}
	}

	if meta != nil {
		if meta.Cancel != nil {
			meta.Cancel()
			waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := waitForStoppedCh(waitCtx, meta.StoppedCh); err != nil {
				logger.Error(err, "Failed to stop event watcher", "object", key)
			}
		} else {
			logger.Error(fmt.Errorf("nil cancel function"), "event watcher has nil cancel function", "object", key)
		}
	}

	wsClient, err := cfg.Client.WebsocketClient(cfg.WatchPath)
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}

	objCopy := cfg.Object.DeepCopyObject()
	obj, ok := objCopy.(client.Object)
	if !ok {
		return fmt.Errorf("failed to convert object copy to client.Object: %T", objCopy)
	}

	watchCtx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)
	cfg.Registry.Register(key, &eventWatcherMeta{
		Cancel:         cancel,
		LastClientID:   cfg.Client.ID(),
		LastGeneration: cfg.Object.GetGeneration(),
		StoppedCh:      stoppedCh,
	})

	go cfg.runEventStream(watchCtx, key, obj, wsClient, stoppedCh)
	return nil
}

// StopInstantUpdateWatcher cancels any running watcher for the provided object.
func StopInstantUpdateWatcher(registry *eventWatcherRegistry, obj client.Object) {
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

func (cfg InstantUpdateConfig) runEventStream(ctx context.Context, key types.NamespacedName, obj client.Object, wsClient *vault.WebsocketClient, stoppedCh chan struct{}) {
	logger := cfg.Logger.WithName("instantUpdateWatcher").WithValues("namespace", obj.GetNamespace(), "name", obj.GetName())
	defer func() {
		cfg.Registry.Delete(key)
		close(stoppedCh)
	}()

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
					cfg.enqueueForReconcile(key)
					return
				}
				time.Sleep(nextBackoff)
			}

			err := cfg.Stream(ctx, obj, wsClient)
			if err == nil {
				shouldBackoff = false
				errorCount = 0
				retryBackoff.Reset()
				continue
			}

			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "context canceled") {
				logger.V(consts.LogLevelDebug).Info("Websocket client closed, stopping watcher")
				return
			}

			errorCount++
			shouldBackoff = true

			if cfg.Recorder != nil {
				cfg.Recorder.Eventf(obj, corev1.EventTypeWarning, consts.ReasonEventWatcherError,
					"Error while watching events: %s", err)
			}

			if errorCount >= instantUpdateErrorThreshold {
				logger.Error(err, "Too many errors while watching events, requeuing")
				cfg.enqueueForReconcile(key)
				return
			}

			newClient, clientErr := cfg.NewClientFunc(ctx, obj)
			if clientErr != nil {
				logger.Error(clientErr, "Failed to retrieve Vault client")
				cfg.enqueueForReconcile(key)
				return
			}

			wsClient, clientErr = newClient.WebsocketClient(cfg.WatchPath)
			if clientErr != nil {
				logger.Error(clientErr, "Failed to create new websocket client")
				cfg.enqueueForReconcile(key)
				return
			}

			meta, ok := cfg.Registry.Get(key)
			if !ok {
				logger.Error(fmt.Errorf("failed to get event watcher metadata"), "missing metadata", "object", key)
				cfg.enqueueForReconcile(key)
				return
			}

			meta.LastClientID = newClient.ID()
			cfg.Registry.Register(key, meta)
		}
	}
}

func (cfg InstantUpdateConfig) enqueueForReconcile(key types.NamespacedName) {
	if cfg.SourceCh == nil || cfg.EventObjectFactory == nil {
		return
	}
	cfg.SourceCh <- event.GenericEvent{
		Object: cfg.EventObjectFactory(key),
	}
}

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
