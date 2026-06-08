// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
	// maxReconnectElapsedTime is set to 0 to retry indefinitely (until context is cancelled).
	// This matches the main branch behavior where WebSocket goroutines keep retrying
	// until they succeed or are explicitly stopped. The SharedWebSocket will keep
	// retrying to reconnect when Vault is down, and automatically recover when Vault
	// comes back up, without requiring external triggers (requeue events or periodic
	// reconciliation).
	maxReconnectElapsedTime = 0
)

// SharedWebSocket manages a single WebSocket connection with multiple subscribers
type SharedWebSocket struct {
	// conn is the underlying WebSocket connection
	conn *websocket.Conn
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

	// Create cancellable context
	wsCtx, cancel := context.WithCancel(context.Background())

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
// It reconnects automatically with exponential backoff (with jitter) on
// transient errors, using the same cenkalti/backoff library as the rest of
// the project.
func (ws *SharedWebSocket) eventLoop() {
	defer func() {
		ws.logger.Info("Event loop exiting", "subscribers", ws.GetSubscriberCount())
		// Notify all subscribers that the WebSocket is stopping
		ws.notifySubscribersOfStop()
	}()

	ws.logger.Info("Event loop started")

	for {
		select {
		case <-ws.ctx.Done():
			ws.logger.V(consts.LogLevelDebug).Info("Context cancelled, stopping event loop")
			if ws.conn != nil {
				ws.conn.Close(websocket.StatusNormalClosure, "context cancelled")
			}
			return
		default:
			err := ws.readAndRoute()
			if err == nil {
				continue
			}

			// Check if the context was cancelled (clean shutdown)
			if ws.ctx.Err() != nil {
				return
			}

			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "context canceled") {
				ws.logger.V(consts.LogLevelDebug).Info("WebSocket closed, stopping event loop")
				return
			}

			ws.logger.Error(err, "WebSocket read error, attempting reconnect with backoff")

			// Reconnect with exponential backoff + jitter, consistent with
			// project-wide patterns (BackOffRegistry, helpers, cache_storage).
			bo := backoff.NewExponentialBackOff(
				backoff.WithInitialInterval(initialReconnectDelay),
				backoff.WithMaxInterval(maxReconnectDelay),
				backoff.WithMaxElapsedTime(maxReconnectElapsedTime),
			)
			reconnErr := backoff.Retry(func() error {
				if reconnErr := ws.reconnect(); reconnErr != nil {
					ws.logger.Error(reconnErr, "Failed to reconnect, will retry")
					return reconnErr
				}
				return nil
			}, backoff.WithContext(bo, ws.ctx))

			if reconnErr != nil {
				ws.logger.Error(reconnErr, "Failed to reconnect after backoff, stopping event loop")
				return
			}
			ws.logger.Info("Successfully reconnected to WebSocket")
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
				ws.logger.V(consts.LogLevelDebug).Info("Calling OnStop callback",
					"subscriber", subKey)
				sub.OnStop()
			}

			// Send requeue event to trigger reconciliation
			select {
			case sub.ReconcileCh <- event.GenericEvent{
				Object: &secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      sub.ResourceKey.Name,
						Namespace: sub.ResourceKey.Namespace,
					},
				},
			}:
				ws.logger.Info("Sent requeue event for reconciliation",
					"subscriber", subKey)
			default:
				ws.logger.V(consts.LogLevelDebug).Info("ReconcileCh full, skipping requeue",
					"subscriber", subKey)
			}
		}
	}
}

// readAndRoute reads a single message from the WebSocket and routes it.
// Uses sync.Pool to reduce GC pressure for unmatched events.
func (ws *SharedWebSocket) readAndRoute() error {
	msgType, message, err := ws.conn.Read(ws.ctx)
	if err != nil {
		return fmt.Errorf("failed to read from websocket: %w", err)
	}

	// Acquire a pooled EventMessage to reduce allocations
	msg := eventMessagePool.Get().(*EventMessage)
	defer eventMessagePool.Put(msg)

	// Zero out before reuse
	msg.Data.Event.Metadata.Path = ""
	msg.Data.Event.Metadata.Modified = ""
	msg.Data.Namespace = ""

	if err := json.Unmarshal(message, msg); err != nil {
		ws.logger.Error(err, "Failed to unmarshal event message")
		return nil // continue processing, don't reconnect on parse errors
	}

	ws.logger.V(consts.LogLevelTrace).Info("Event received",
		"messageType", msgType,
		"namespace", msg.Data.Namespace,
		"path", msg.Data.Event.Metadata.Path,
		"modified", msg.Data.Event.Metadata.Modified)

	ws.routeEvent(msg)
	return nil
}

// reconnect creates a new WebSocket connection, replacing the old one
func (ws *SharedWebSocket) reconnect() error {
	// Close old connection if still open
	if ws.conn != nil {
		ws.conn.Close(websocket.StatusNormalClosure, "reconnecting")
	}

	wsClient, err := ws.vaultClient.WebsocketClient(getEventPath(ws.eventType))
	if err != nil {
		return fmt.Errorf("failed to create websocket client: %w", err)
	}

	conn, err := wsClient.Connect(ws.ctx)
	if err != nil {
		return fmt.Errorf("failed to connect websocket: %w", err)
	}
	ws.conn = conn
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
	vaultPath := msg.Data.Event.Metadata.Path

	lookupKey := SubscriptionKey{
		VaultNamespace: vaultNS,
		VaultPath:      vaultPath,
	}.String()

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

	for _, sub := range subsCopy {
		var obj client.Object
		switch sub.ResourceType {
		case "VaultStaticSecret":
			obj = &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: sub.ResourceKey.Namespace,
					Name:      sub.ResourceKey.Name,
				},
			}
		case "VaultDynamicSecret":
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

// Close gracefully shuts down the WebSocket
func (ws *SharedWebSocket) Close() error {
	ws.logger.Info("Closing SharedWebSocket", "subscribers", ws.GetSubscriberCount())

	// Cancel context to stop event loop
	ws.cancel()

	// Close WebSocket connection
	if ws.conn != nil {
		err := ws.conn.Close(websocket.StatusNormalClosure, "closing shared websocket")
		if err != nil {
			ws.logger.Error(err, "Error closing websocket connection")
			return err
		}
	}

	ws.logger.Info("SharedWebSocket closed")
	return nil
}

// IsHealthy checks if the WebSocket is still healthy
func (ws *SharedWebSocket) IsHealthy() bool {
	select {
	case <-ws.ctx.Done():
		return false
	default:
		return ws.conn != nil
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
