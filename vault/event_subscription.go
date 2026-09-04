// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/coder/websocket"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

const (
	// reconnection backoff constants
	initialReconnectDelay = 1 * time.Second
	maxReconnectDelay     = 60 * time.Second
	// maxReconnectErrorThreshold is the number of consecutive reconnect failures
	// allowed for a single SharedWebSocket instance before the event loop gives up
	// and stops. Stopping triggers notifySubscribersOfStop(), which requeues all
	// subscriber CRs for reconciliation so a fresh SharedWebSocket can be created.
	maxReconnectErrorThreshold = 5
)

// SharedWebSocket manages a single WebSocket connection with multiple subscribers
type SharedWebSocket struct {
	// conn is the underlying WebSocket connection.
	// All cross-goroutine accesses snapshot the pointer under connMu.RLock for
	// just the load, then release before calling any method on the connection.
	// This protects the pointer against a concurrent Close() zeroing it while
	// never holding connMu across a blocking network call.
	conn   *websocket.Conn
	connMu sync.RWMutex
	// stopped indicates that the event loop has exited and this websocket should
	// no longer be considered healthy or reusable. Written by the event-loop
	// goroutine and read from reconciler goroutines via IsHealthy(), so it must
	// be accessed atomically to avoid a data race.
	stopped atomic.Bool
	// notifyOnStop indicates that subscribers should be requeued because the
	// event loop is exiting due to reconnect failure exhaustion.
	notifyOnStop bool
	// eventType is the type of events this WebSocket subscribes to
	eventType EventType
	// subscribers maps SubscriptionKey -> (subscriberKey -> *Subscriber)
	// This supports multiple CRs subscribing to the same Vault path.
	subscribers map[string]map[string]*Subscriber
	// subscriberMu protects the subscribers map
	subscriberMu sync.RWMutex
	// ctx is the context for this WebSocket
	ctx context.Context
	// cancel cancels the context and stops the event loop
	cancel context.CancelFunc
	// vaultClient is the Vault client that owns this WebSocket
	vaultClient Client
	// logger is the logger for this WebSocket
	logger logr.Logger
	// clientID is the ID of the client that owns this WebSocket
	clientID string
	// onStop is called once when the event loop exits so the owning client can
	// remove this websocket from its registry.
	onStop func()
}

// NewSharedWebSocket creates a new shared WebSocket connection
func NewSharedWebSocket(
	ctx context.Context,
	vaultClient Client,
	eventType EventType,
) (*SharedWebSocket, error) {
	logger := log.FromContext(ctx).WithName("SharedWebSocket").WithValues(
		"eventType", eventType,
		"clientID", vaultClient.ID(),
	)

	// Create WebSocket client
	wsClient, err := vaultClient.WebsocketClient(getEventPath(eventType))
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket client: %w", err)
	}

	// Create cancellable context derived from the caller's context so that
	// the event-loop goroutine is cancelled when the parent (manager) context
	// is cancelled on operator shutdown.
	wsCtx, cancel := context.WithCancel(ctx)

	ws := &SharedWebSocket{
		eventType:   eventType,
		subscribers: make(map[string]map[string]*Subscriber),
		ctx:         wsCtx,
		cancel:      cancel,
		vaultClient: vaultClient,
		logger:      logger,
		clientID:    vaultClient.ID(),
	}

	// Connect to Vault
	conn, err := wsClient.Connect(wsCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect websocket: %w", err)
	}
	ws.conn = conn

	logger.Info("SharedWebSocket created and connected")

	// Start event loop in background
	go ws.eventLoop()

	return ws, nil
}

// Subscribe adds a subscriber to this WebSocket.
// Multiple subscribers can watch the same Vault path (e.g. two CRs referencing the same secret).
func (ws *SharedWebSocket) Subscribe(sub *Subscriber) error {
	if sub == nil {
		return fmt.Errorf("subscriber cannot be nil")
	}

	pathKey := SubscriptionKey{
		VaultNamespace: sub.VaultNS,
		VaultPath:      sub.VaultPath,
	}.String()
	subKey := subscriberKey(sub)

	ws.subscriberMu.Lock()
	defer ws.subscriberMu.Unlock()

	if ws.subscribers[pathKey] == nil {
		ws.subscribers[pathKey] = make(map[string]*Subscriber)
	}
	ws.subscribers[pathKey][subKey] = sub

	ws.logger.V(consts.LogLevelDebug).Info("Subscriber added",
		"pathKey", pathKey,
		"resource", sub.ResourceKey,
		"resourceType", sub.ResourceType,
		"totalPaths", len(ws.subscribers),
		"subsForPath", len(ws.subscribers[pathKey]))

	return nil
}

// Unsubscribe removes a subscriber from this WebSocket.
// Returns true if there are no subscribers remaining across all paths.
func (ws *SharedWebSocket) Unsubscribe(pathKey SubscriptionKey, resourceKey string) bool {
	ws.subscriberMu.Lock()
	defer ws.subscriberMu.Unlock()

	pk := pathKey.String()
	if subs, exists := ws.subscribers[pk]; exists {
		delete(subs, resourceKey)
		if len(subs) == 0 {
			delete(ws.subscribers, pk)
		}
		ws.logger.V(consts.LogLevelDebug).Info("Subscriber removed",
			"pathKey", pk,
			"resource", resourceKey,
			"remainingPaths", len(ws.subscribers))
	}

	return len(ws.subscribers) == 0
}

// GetSubscriberCount returns the total number of subscribers across all paths
func (ws *SharedWebSocket) GetSubscriberCount() int {
	ws.subscriberMu.RLock()
	defer ws.subscriberMu.RUnlock()
	total := 0
	for _, subs := range ws.subscribers {
		total += len(subs)
	}
	return total
}

// eventLoop reads events from the WebSocket and routes them to subscribers.
// On read failures it retries reconnect with exponential backoff. After too
// many consecutive reconnect failures, the loop stops and subscribers are
// requeued so reconciliation can create a fresh SharedWebSocket instance.
func (ws *SharedWebSocket) eventLoop() {
	defer func() {
		ws.stopped.Store(true)
		ws.logger.Info("Event loop exiting", "subscribers", ws.GetSubscriberCount())
		if ws.notifyOnStop {
			// Notify all subscribers that the WebSocket is stopping due to failure.
			ws.notifySubscribersOfStop()
		}
		if ws.onStop != nil {
			ws.onStop()
		}
	}()

	ws.logger.Info("Event loop started")

	bo := backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(initialReconnectDelay),
		backoff.WithMaxInterval(maxReconnectDelay),
	)
	bo.Reset()
	errorCount := 0

	for {
		select {
		case <-ws.ctx.Done():
			ws.logger.V(consts.LogLevelDebug).Info("Context cancelled, stopping event loop")
			ws.connMu.RLock()
			conn := ws.conn
			ws.connMu.RUnlock()
			if conn != nil {
				conn.Close(websocket.StatusNormalClosure, "context cancelled")
			}
			return
		default:
			err := ws.readAndRoute()
			if err == nil {
				errorCount = 0
				bo.Reset()
				continue
			}

			if ws.ctx.Err() != nil {
				return
			}

			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "context canceled") {
				ws.logger.V(consts.LogLevelDebug).Info("WebSocket closed, stopping event loop")
				return
			}

			ws.logger.Error(err, "WebSocket read error, attempting reconnect with backoff")

			for {
				if reconnErr := ws.reconnect(); reconnErr != nil {
					errorCount++
					ws.logger.Error(reconnErr, "Failed to reconnect", "errorCount", errorCount)
					if errorCount >= maxReconnectErrorThreshold {
						ws.logger.Error(reconnErr, "Too many reconnect failures, stopping event loop",
							"errorCount", errorCount, "threshold", maxReconnectErrorThreshold)
						ws.notifyOnStop = true
						ws.connMu.RLock()
						conn := ws.conn
						ws.connMu.RUnlock()
						if conn != nil {
							conn.Close(websocket.StatusNormalClosure, "reconnect threshold reached")
						}
						ws.cancel()
						return
					}

					nextBackoff := bo.NextBackOff()
					select {
					case <-ws.ctx.Done():
						return
					case <-time.After(nextBackoff):
					}
					continue
				}

				ws.logger.Info("Successfully reconnected to WebSocket", "errorCount", errorCount)
				errorCount = 0
				bo.Reset()
				break
			}
		}
	}
}

// notifySubscribersOfStop notifies all subscribers that the WebSocket is stopping
// and triggers reconciliation by sending a requeue event.
func (ws *SharedWebSocket) notifySubscribersOfStop() {
	ws.subscriberMu.RLock()
	defer ws.subscriberMu.RUnlock()

	for pathKey, subs := range ws.subscribers {
		for subKey, sub := range subs {
			ws.logger.V(consts.LogLevelDebug).Info("Notifying subscriber of stop",
				"pathKey", pathKey,
				"subscriber", subKey,
				"resourceType", sub.ResourceType)

			// Call OnStop callback for cleanup
			if sub.OnStop != nil {
				ws.logger.Info("WebSocket stopped, cleaning up registry entry",
					"subscriber", subKey,
					"resourceType", sub.ResourceType)
				sub.OnStop()
			}

			// Send requeue event to trigger reconciliation.
			// NewObject may be nil for subscribers created before this field was
			// introduced; skip the requeue rather than panic in that case.
			if sub.NewObject == nil {
				ws.logger.V(consts.LogLevelDebug).Info("Skipping requeue: NewObject not set",
					"subscriber", subKey)
				continue
			}
			evt := event.GenericEvent{Object: sub.NewObject()}
			select {
			case sub.ReconcileCh <- evt:
				ws.logger.Info("Sent requeue event for reconciliation",
					"subscriber", subKey)
			default:
				// Channel is full. For normal events a drop is fine because
				// another event will follow, but this is the only signal that
				// wakes the reconciler after a WebSocket dies — dropping it
				// would leave the resource unsubscribed until the next periodic
				// resync. Spawn a goroutine to block-send so delivery is
				// guaranteed without holding the subscriber lock.
				ch := sub.ReconcileCh
				ctx := ws.ctx
				go func() {
					select {
					case ch <- evt:
					case <-ctx.Done():
					}
				}()
				ws.logger.V(consts.LogLevelDebug).Info("ReconcileCh full, scheduled async requeue",
					"subscriber", subKey)
			}
		}
	}
}

// readAndRoute reads a single message from the WebSocket and routes it.
// Uses sync.Pool to reduce GC pressure for unmatched events.
func (ws *SharedWebSocket) readAndRoute() error {
	ws.connMu.RLock()
	conn := ws.conn
	ws.connMu.RUnlock()
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	msgType, message, err := conn.Read(ws.ctx)
	if err != nil {
		return fmt.Errorf("failed to read from websocket: %w", err)
	}

	// Acquire a pooled EventMessage to reduce allocations
	msg := eventMessagePool.Get().(*EventMessage)
	defer eventMessagePool.Put(msg)

	// Zero out before reuse
	msg.Data.Event.Metadata.Path = ""
	msg.Data.Event.Metadata.Modified = ""
	msg.Data.Event.Metadata.Name = ""
	msg.Data.Event.Metadata.Operation = ""
	msg.Data.Event.Metadata.LeaseID = ""
	msg.Data.Event.Metadata.VaultIndex = ""
	msg.Data.EventType = ""
	msg.Data.Namespace = ""
	msg.Data.PluginInfo.MountPath = ""
	msg.Data.PluginInfo.Plugin = ""

	if err := json.Unmarshal(message, msg); err != nil {
		ws.logger.Error(err, "Failed to unmarshal event message")
		return nil // continue processing, don't reconnect on parse errors
	}

	ws.logger.V(consts.LogLevelTrace).Info("Event received",
		"messageType", msgType,
		"namespace", msg.Data.Namespace,
		"path", msg.Data.Event.Metadata.Path,
		"modified", msg.Data.Event.Metadata.Modified,
		"name", msg.Data.Event.Metadata.Name,
		"eventType", msg.Data.EventType)

	ws.routeEvent(msg)
	return nil
}

// reconnect creates a new WebSocket connection, replacing the old one.
// Called exclusively from the event-loop goroutine; connMu is held only around
// the conn pointer swap so that IsHealthy (which runs on reconciler goroutines)
// never observes a torn read.
func (ws *SharedWebSocket) reconnect() error {
	// Snapshot and clear the old conn under write lock, then close it without
	// holding the lock (Close can block briefly).
	ws.connMu.Lock()
	old := ws.conn
	ws.conn = nil
	ws.connMu.Unlock()

	if old != nil {
		old.Close(websocket.StatusNormalClosure, "reconnecting")
	}

	wsClient, err := ws.vaultClient.WebsocketClient(getEventPath(ws.eventType))
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}

	conn, err := wsClient.Connect(ws.ctx)
	if err != nil {
		return fmt.Errorf("failed to connect websocket: %w", err)
	}

	ws.connMu.Lock()
	ws.conn = conn
	ws.connMu.Unlock()
	return nil
}

// routeEvent matches the event to subscribers and triggers reconciliation
func (ws *SharedWebSocket) routeEvent(msg *EventMessage) {
	modified, err := parseutil.ParseBool(msg.Data.Event.Metadata.Modified)
	if err != nil {
		ws.logger.V(consts.LogLevelDebug).Info("Failed to parse modified field",
			"error", err,
			"value", msg.Data.Event.Metadata.Modified)
		return
	}

	if !modified {
		return
	}

	vaultNS := strings.Trim(msg.Data.Namespace, "/")

	var lookupKey string
	switch ws.eventType {
	case EventTypeKV:
		lookupKey = SubscriptionKey{
			VaultNamespace: vaultNS,
			VaultPath:      msg.Data.Event.Metadata.Path,
		}.String()
	case EventTypeLease:
		// Skip routine lease renewal events — these are generated by VSO's own
		// LifetimeWatcher and would cause a reconciliation feedback loop.
		// We only care about revoke/expire which indicate credential changes.
		if msg.Data.Event.Metadata.Operation == "renew" {
			ws.logger.V(consts.LogLevelTrace).Info("Ignoring lease renewal event",
				"leaseID", msg.Data.Event.Metadata.LeaseID)
			return
		}
		// Route by lease ID — subscribers register with their lease ID as key.
		// Lease IDs are globally unique and Vault lease events don't include
		// a namespace field, so namespace is intentionally omitted.
		leaseID := msg.Data.Event.Metadata.LeaseID
		if leaseID == "" {
			return
		}
		lookupKey = SubscriptionKey{
			VaultPath: leaseID,
		}.String()
	default:
		// Route by mount + role name instead of exact path, since the event
		// path (e.g. "database/rotate-role/my-role") differs from the read
		// path (e.g. "database/static-creds/my-role").
		roleName := msg.Data.Event.Metadata.Name
		mount := strings.TrimSuffix(msg.Data.PluginInfo.MountPath, "/")
		if roleName == "" || mount == "" {
			// Fallback: extract from path for events missing plugin_info
			mount, roleName = extractMountAndRole(msg.Data.Event.Metadata.Path)
		}
		if roleName == "" {
			return
		}
		lookupKey = SubscriptionKey{
			VaultNamespace: vaultNS,
			VaultPath:      mount + "/" + roleName,
		}.String()
	}

	ws.subscriberMu.RLock()
	subs, exists := ws.subscribers[lookupKey]
	if !exists {
		ws.subscriberMu.RUnlock()
		return
	}
	// Copy subscriber list under read lock to avoid holding it during channel sends
	subsCopy := make([]*Subscriber, 0, len(subs))
	for _, sub := range subs {
		subsCopy = append(subsCopy, sub)
	}
	ws.subscriberMu.RUnlock()

	ws.logger.V(consts.LogLevelDebug).Info("Event matched subscribers",
		"key", lookupKey,
		"count", len(subsCopy))

	vaultIndex := strings.TrimSpace(msg.Data.Event.Metadata.VaultIndex)

	for _, sub := range subsCopy {
		var obj client.Object
		switch sub.ResourceType {
		case ResourceTypeVaultStaticSecret:
			obj = &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: sub.ResourceKey.Namespace,
					Name:      sub.ResourceKey.Name,
				},
			}
		case ResourceTypeVaultDynamicSecret:
			obj = &secretsv1beta1.VaultDynamicSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: sub.ResourceKey.Namespace,
					Name:      sub.ResourceKey.Name,
				},
			}
		default:
			ws.logger.Error(fmt.Errorf("unknown resource type: %s", sub.ResourceType),
				"Skipping subscriber", "resource", sub.ResourceKey)
			continue
		}

		// Store vault_index before sending the reconcile event so the reconciler
		// can attach X-Vault-Index to the subsequent Vault read, ensuring it is
		// served from a node that has replicated the write.
		if sub.PendingVaultIndex != nil && vaultIndex != "" {
			sub.PendingVaultIndex.Store(sub.ResourceKey, vaultIndex)
		}

		select {
		case sub.ReconcileCh <- event.GenericEvent{Object: obj}:
			ws.logger.V(consts.LogLevelTrace).Info("Reconciliation event sent",
				"resource", sub.ResourceKey)
		default:
			ws.logger.V(consts.LogLevelWarning).Info("Reconciliation channel full, dropping event",
				"resource", sub.ResourceKey)
		}
	}
}

// Close gracefully shuts down the WebSocket.
// May be called from any goroutine (reconciler, manager shutdown).
func (ws *SharedWebSocket) Close() error {
	ws.logger.Info("Closing SharedWebSocket", "subscribers", ws.GetSubscriberCount())

	// Cancel context to stop event loop
	ws.cancel()

	// Snapshot and clear conn under write lock so that a concurrent IsHealthy
	// call never reads a partially-closed connection.
	ws.connMu.Lock()
	conn := ws.conn
	ws.conn = nil
	ws.connMu.Unlock()

	if conn != nil {
		if err := conn.Close(websocket.StatusNormalClosure, "closing shared websocket"); err != nil {
			ws.logger.Error(err, "Error closing websocket connection")
			return err
		}
	}

	ws.logger.Info("SharedWebSocket closed")
	return nil
}

// IsHealthy checks if the WebSocket is still healthy.
// May be called from any goroutine; uses connMu to safely read ws.conn.
func (ws *SharedWebSocket) IsHealthy() bool {
	if ws.stopped.Load() {
		return false
	}
	select {
	case <-ws.ctx.Done():
		return false
	default:
		ws.connMu.RLock()
		healthy := ws.conn != nil
		ws.connMu.RUnlock()
		return healthy
	}
}

// GetEventType returns the event type this WebSocket subscribes to
func (ws *SharedWebSocket) GetEventType() EventType {
	return ws.eventType
}

// GetClientID returns the ID of the client that owns this WebSocket
func (ws *SharedWebSocket) GetClientID() string {
	return ws.clientID
}
