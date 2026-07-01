// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// EventType represents different Vault event types
type EventType string

const (
	// EventTypeKV represents KV secret engine events
	EventTypeKV EventType = "kv"
	// EventTypeDatabase represents database secret engine events
	EventTypeDatabase EventType = "database"
	// EventTypePKI represents PKI secret engine events
	EventTypePKI EventType = "pki"
)

// String returns the string representation of the EventType
func (e EventType) String() string {
	return string(e)
}

// EventMessage represents a Vault event message structure
type EventMessage struct {
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

// eventMessagePool reduces GC pressure under high event volume by reusing
// EventMessage structs. This is important for the "God Token" scenario where
// a single WebSocket may receive events for thousands of secrets that are
// not subscribed to by any CR.
var eventMessagePool = sync.Pool{
	New: func() interface{} {
		return &EventMessage{}
	},
}

// Subscriber represents a resource subscribed to Vault events
type Subscriber struct {
	// ResourceKey is the Kubernetes namespace/name of the resource
	ResourceKey types.NamespacedName
	// VaultNS is the Vault namespace to match
	VaultNS string
	// VaultPath is the Vault path to match
	VaultPath string
	// ResourceType identifies the type of resource (e.g., "VaultStaticSecret")
	ResourceType string
	// ReconcileCh is the channel to send reconciliation events to
	ReconcileCh chan event.GenericEvent
	// OnStop is called when the WebSocket event loop stops
	OnStop func()
}

// SubscriptionKey uniquely identifies a subscription based on Vault namespace and path
type SubscriptionKey struct {
	VaultNamespace string
	VaultPath      string
}

// String returns the string representation of the SubscriptionKey
func (k SubscriptionKey) String() string {
	if k.VaultNamespace == "" {
		return k.VaultPath
	}
	return fmt.Sprintf("%s/%s", k.VaultNamespace, k.VaultPath)
}

// subscriberKey uniquely identifies a single subscriber within a path.
// Multiple CRs can subscribe to the same Vault path.
func subscriberKey(sub *Subscriber) string {
	return sub.ResourceKey.String()
}

// getEventPath returns the Vault event subscription path for the given event type
func getEventPath(eventType EventType) string {
	paths := map[EventType]string{
		EventTypeKV:       "/v1/sys/events/subscribe/kv*",
		EventTypeDatabase: "/v1/sys/events/subscribe/database*",
		EventTypePKI:      "/v1/sys/events/subscribe/pki*",
	}
	return paths[eventType]
}
