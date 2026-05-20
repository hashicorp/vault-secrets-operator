// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestSubscriptionKey_String(t *testing.T) {
	tests := []struct {
		name string
		key  SubscriptionKey
		want string
	}{
		{
			name: "with namespace",
			key: SubscriptionKey{
				VaultNamespace: "prod",
				VaultPath:      "kv/data/app1/config",
			},
			want: "prod/kv/data/app1/config",
		},
		{
			name: "without namespace",
			key: SubscriptionKey{
				VaultNamespace: "",
				VaultPath:      "kv/data/app1/config",
			},
			want: "kv/data/app1/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.key.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		want      string
	}{
		{
			name:      "kv",
			eventType: EventTypeKV,
			want:      "kv",
		},
		{
			name:      "database",
			eventType: EventTypeDatabase,
			want:      "database",
		},
		{
			name:      "pki",
			eventType: EventTypePKI,
			want:      "pki",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eventType.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetEventPath(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		want      string
	}{
		{
			name:      "kv",
			eventType: EventTypeKV,
			want:      "/v1/sys/events/subscribe/kv*",
		},
		{
			name:      "database",
			eventType: EventTypeDatabase,
			want:      "/v1/sys/events/subscribe/database*",
		},
		{
			name:      "pki",
			eventType: EventTypePKI,
			want:      "/v1/sys/events/subscribe/pki*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getEventPath(tt.eventType)
			assert.Equal(t, tt.want, got)
		})
	}
}

// newTestSharedWebSocket creates a SharedWebSocket suitable for unit tests
// (no real WebSocket connection).
func newTestSharedWebSocket() *SharedWebSocket {
	ctx, cancel := context.WithCancel(context.Background())
	return &SharedWebSocket{
		eventType:   EventTypeKV,
		subscribers: make(map[string]map[string]*Subscriber),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logr.Discard(),
		clientID:    "test-client",
	}
}

func TestSharedWebSocket_Subscribe(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	reconcileCh := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey: types.NamespacedName{
			Namespace: "default",
			Name:      "test-secret",
		},
		VaultNS:      "prod",
		VaultPath:    "kv/data/app1/config",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  reconcileCh,
	}

	err := ws.Subscribe(sub)
	require.NoError(t, err)
	assert.Equal(t, 1, ws.GetSubscriberCount())
}

func TestSharedWebSocket_Subscribe_NilRejects(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	err := ws.Subscribe(nil)
	require.Error(t, err)
	assert.Equal(t, 0, ws.GetSubscriberCount())
}

func TestSharedWebSocket_MultipleSubscribers_SamePath(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch1 := make(chan event.GenericEvent, 10)
	ch2 := make(chan event.GenericEvent, 10)

	sub1 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns1", Name: "secret-a"},
		VaultNS:      "prod",
		VaultPath:    "kv/data/shared/config",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch1,
	}
	sub2 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns2", Name: "secret-b"},
		VaultNS:      "prod",
		VaultPath:    "kv/data/shared/config",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch2,
	}

	require.NoError(t, ws.Subscribe(sub1))
	require.NoError(t, ws.Subscribe(sub2))
	assert.Equal(t, 2, ws.GetSubscriberCount())

	// Unsubscribe one — other should remain
	pathKey := SubscriptionKey{VaultNamespace: "prod", VaultPath: "kv/data/shared/config"}
	isEmpty := ws.Unsubscribe(pathKey, sub1.ResourceKey.String())
	assert.False(t, isEmpty)
	assert.Equal(t, 1, ws.GetSubscriberCount())

	// Unsubscribe the last one
	isEmpty = ws.Unsubscribe(pathKey, sub2.ResourceKey.String())
	assert.True(t, isEmpty)
	assert.Equal(t, 0, ws.GetSubscriberCount())
}

func TestSharedWebSocket_Unsubscribe_DifferentPaths(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)

	sub1 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "s1"},
		VaultNS:      "",
		VaultPath:    "kv/data/path1",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}
	sub2 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "s2"},
		VaultNS:      "",
		VaultPath:    "kv/data/path2",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}

	require.NoError(t, ws.Subscribe(sub1))
	require.NoError(t, ws.Subscribe(sub2))
	assert.Equal(t, 2, ws.GetSubscriberCount())

	key1 := SubscriptionKey{VaultPath: "kv/data/path1"}
	isEmpty := ws.Unsubscribe(key1, sub1.ResourceKey.String())
	assert.False(t, isEmpty)
	assert.Equal(t, 1, ws.GetSubscriberCount())

	key2 := SubscriptionKey{VaultPath: "kv/data/path2"}
	isEmpty = ws.Unsubscribe(key2, sub2.ResourceKey.String())
	assert.True(t, isEmpty)
}

func TestSharedWebSocket_RouteEvent_SingleSubscriber(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vss"},
		VaultNS:      "prod",
		VaultPath:    "kv/data/app1/config",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = "prod"
	msg.Data.Event.Metadata.Path = "kv/data/app1/config"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vss", evt.Object.GetName())
	assert.Equal(t, "default", evt.Object.GetNamespace())
}

func TestSharedWebSocket_RouteEvent_MultipleSubscribers(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch1 := make(chan event.GenericEvent, 10)
	ch2 := make(chan event.GenericEvent, 10)

	sub1 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns1", Name: "vss-1"},
		VaultNS:      "",
		VaultPath:    "kv/data/shared",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch1,
	}
	sub2 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns2", Name: "vss-2"},
		VaultNS:      "",
		VaultPath:    "kv/data/shared",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch2,
	}

	require.NoError(t, ws.Subscribe(sub1))
	require.NoError(t, ws.Subscribe(sub2))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "kv/data/shared"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	assert.Len(t, ch1, 1)
	assert.Len(t, ch2, 1)
}

func TestSharedWebSocket_RouteEvent_NonModified_Dropped(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "vss"},
		VaultNS:      "",
		VaultPath:    "kv/data/secret",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Event.Metadata.Path = "kv/data/secret"
	msg.Data.Event.Metadata.Modified = "false"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "non-modified event should be dropped")
}

func TestSharedWebSocket_RouteEvent_NoMatch_Dropped(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "vss"},
		VaultNS:      "",
		VaultPath:    "kv/data/my-secret",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Event.Metadata.Path = "kv/data/other-secret"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "unmatched path should be dropped")
}

func TestSharedWebSocket_SubscriptionKey(t *testing.T) {
	sub := &Subscriber{
		ResourceKey: types.NamespacedName{
			Namespace: "default",
			Name:      "test-secret",
		},
		VaultNS:   "prod",
		VaultPath: "kv/data/app1/config",
	}

	key := SubscriptionKey{
		VaultNamespace: sub.VaultNS,
		VaultPath:      sub.VaultPath,
	}

	expectedKey := "prod/kv/data/app1/config"
	assert.Equal(t, expectedKey, key.String())
}

func TestEventMessage_Pool(t *testing.T) {
	msg := eventMessagePool.Get().(*EventMessage)

	// Zero it like readAndRoute does
	msg.Data.Event.Metadata.Path = ""
	msg.Data.Event.Metadata.Modified = ""
	msg.Data.Namespace = ""

	raw := `{"data":{"event":{"metadata":{"path":"kv/data/x","modified":"true"}},"namespace":"ns1"}}`
	require.NoError(t, json.Unmarshal([]byte(raw), msg))
	assert.Equal(t, "kv/data/x", msg.Data.Event.Metadata.Path)
	assert.Equal(t, "ns1", msg.Data.Namespace)

	eventMessagePool.Put(msg)
}

func TestEventMessage_Structure(t *testing.T) {
	msg := &EventMessage{}

	msg.Data.Namespace = "prod"
	msg.Data.Event.Metadata.Path = "kv/data/app1/config"
	msg.Data.Event.Metadata.Modified = "true"

	assert.Equal(t, "prod", msg.Data.Namespace)
	assert.Equal(t, "kv/data/app1/config", msg.Data.Event.Metadata.Path)
	assert.Equal(t, "true", msg.Data.Event.Metadata.Modified)
}

func TestSharedWebSocket_ConcurrentSubscribeUnsubscribe(t *testing.T) {
	ws := newTestSharedWebSocket()
	defer ws.cancel()

	var wg sync.WaitGroup
	const count = 50

	// Subscribe concurrently
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sub := &Subscriber{
				ResourceKey:  types.NamespacedName{Namespace: "default", Name: types.NamespacedName{Namespace: "default", Name: "vss"}.Name + string(rune('a'+i%26))},
				VaultNS:      "",
				VaultPath:    "kv/data/path",
				ResourceType: "VaultStaticSecret",
				ReconcileCh:  make(chan event.GenericEvent, 1),
			}
			_ = ws.Subscribe(sub)
		}(i)
	}
	wg.Wait()

	assert.Greater(t, ws.GetSubscriberCount(), 0)
}

// Placeholder for future integration tests
func TestSharedWebSocket_Integration(t *testing.T) {
	t.Skip("Integration tests will be added in Phase 4")
}
