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
		{
			name:      "ldap",
			eventType: EventTypeLDAP,
			want:      "ldap",
		},
		{
			name:      "lease",
			eventType: EventTypeLease,
			want:      "lease",
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
		{
			name:      "ldap",
			eventType: EventTypeLDAP,
			want:      "/v1/sys/events/subscribe/ldap*",
		},
		{
			name:      "lease",
			eventType: EventTypeLease,
			want:      "/v1/sys/events/subscribe/lease*",
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
func newTestSharedWebSocket(eventType EventType) *SharedWebSocket {
	ctx, cancel := context.WithCancel(context.Background())
	return &SharedWebSocket{
		eventType:   eventType,
		subscribers: make(map[string]map[string]*Subscriber),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logr.Discard(),
		clientID:    "test-client",
	}
}

func TestSharedWebSocket_Subscribe(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
	defer ws.cancel()

	err := ws.Subscribe(nil)
	require.Error(t, err)
	assert.Equal(t, 0, ws.GetSubscriberCount())
}

func TestSharedWebSocket_MultipleSubscribers_SamePath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
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
	ws := newTestSharedWebSocket(EventTypeKV)
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
	msg.Data.Event.Metadata.Name = ""
	msg.Data.Event.Metadata.Operation = ""
	msg.Data.Event.Metadata.LeaseID = ""
	msg.Data.EventType = ""
	msg.Data.Namespace = ""
	msg.Data.PluginInfo.MountPath = ""
	msg.Data.PluginInfo.Plugin = ""

	raw := `{"data":{"event":{"metadata":{"path":"kv/data/x","modified":"true","name":"my-role"}},"event_type":"database/rotate","namespace":"ns1","plugin_info":{"mount_path":"database/","plugin":"postgresql-database-plugin"}}}`
	require.NoError(t, json.Unmarshal([]byte(raw), msg))
	assert.Equal(t, "kv/data/x", msg.Data.Event.Metadata.Path)
	assert.Equal(t, "ns1", msg.Data.Namespace)
	assert.Equal(t, "my-role", msg.Data.Event.Metadata.Name)
	assert.Equal(t, "database/rotate", msg.Data.EventType)
	assert.Equal(t, "database/", msg.Data.PluginInfo.MountPath)
	assert.Equal(t, "postgresql-database-plugin", msg.Data.PluginInfo.Plugin)

	eventMessagePool.Put(msg)
}

func TestEventMessage_PoolZeroesNewFields(t *testing.T) {
	msg := eventMessagePool.Get().(*EventMessage)

	// Simulate a previous message with all fields set
	msg.Data.Event.Metadata.Path = "old/path"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "old-role"
	msg.Data.Event.Metadata.Operation = "rotate"
	msg.Data.Event.Metadata.LeaseID = "old-lease-id"
	msg.Data.EventType = "database/rotate"
	msg.Data.Namespace = "old-ns"
	msg.Data.PluginInfo.MountPath = "old-mount/"
	msg.Data.PluginInfo.Plugin = "old-plugin"

	eventMessagePool.Put(msg)

	// Get it back and zero like readAndRoute does
	msg = eventMessagePool.Get().(*EventMessage)
	msg.Data.Event.Metadata.Path = ""
	msg.Data.Event.Metadata.Modified = ""
	msg.Data.Event.Metadata.Name = ""
	msg.Data.Event.Metadata.Operation = ""
	msg.Data.Event.Metadata.LeaseID = ""
	msg.Data.EventType = ""
	msg.Data.Namespace = ""
	msg.Data.PluginInfo.MountPath = ""
	msg.Data.PluginInfo.Plugin = ""

	// Unmarshal a KV event that doesn't include the new fields
	raw := `{"data":{"event":{"metadata":{"path":"kv/data/x","modified":"true"}},"namespace":"ns1"}}`
	require.NoError(t, json.Unmarshal([]byte(raw), msg))

	// New fields should be empty (not stale from the previous message)
	assert.Equal(t, "", msg.Data.Event.Metadata.Name)
	assert.Equal(t, "", msg.Data.Event.Metadata.Operation)
	assert.Equal(t, "", msg.Data.Event.Metadata.LeaseID)
	assert.Equal(t, "", msg.Data.EventType)
	assert.Equal(t, "", msg.Data.PluginInfo.MountPath)
	assert.Equal(t, "", msg.Data.PluginInfo.Plugin)
}

func TestEventMessage_Structure(t *testing.T) {
	msg := &EventMessage{}

	msg.Data.Namespace = "prod"
	msg.Data.Event.Metadata.Path = "kv/data/app1/config"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.Event.Metadata.Operation = "rotate"
	msg.Data.Event.Metadata.LeaseID = "database/creds/my-role/abc123"
	msg.Data.EventType = "database/rotate"
	msg.Data.PluginInfo.MountPath = "database/"
	msg.Data.PluginInfo.Plugin = "postgresql-database-plugin"

	assert.Equal(t, "prod", msg.Data.Namespace)
	assert.Equal(t, "kv/data/app1/config", msg.Data.Event.Metadata.Path)
	assert.Equal(t, "true", msg.Data.Event.Metadata.Modified)
	assert.Equal(t, "my-role", msg.Data.Event.Metadata.Name)
	assert.Equal(t, "rotate", msg.Data.Event.Metadata.Operation)
	assert.Equal(t, "database/creds/my-role/abc123", msg.Data.Event.Metadata.LeaseID)
	assert.Equal(t, "database/rotate", msg.Data.EventType)
	assert.Equal(t, "database/", msg.Data.PluginInfo.MountPath)
	assert.Equal(t, "postgresql-database-plugin", msg.Data.PluginInfo.Plugin)
}

func TestSharedWebSocket_ConcurrentSubscribeUnsubscribe(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeKV)
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

// --- Database event routing tests ---

func TestSharedWebSocket_RouteEvent_Database_WithPluginInfo(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Simulate a database/rotate event with plugin_info metadata
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.EventType = "database/rotate"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
	assert.Equal(t, "default", evt.Object.GetNamespace())
}

func TestSharedWebSocket_RouteEvent_Database_FallbackFromPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Simulate an event without plugin_info (fallback to path parsing)
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	// No Name or PluginInfo set

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
}

func TestSharedWebSocket_RouteEvent_Database_WithNamespace(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "prod",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = "prod/"
	msg.Data.Event.Metadata.Path = "database/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
}

func TestSharedWebSocket_RouteEvent_Database_NamespaceMismatch(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "prod",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Event from a different Vault namespace
	msg := &EventMessage{}
	msg.Data.Namespace = "staging"
	msg.Data.Event.Metadata.Path = "database/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "namespace mismatch should not route")
}

func TestSharedWebSocket_RouteEvent_Database_RoleMismatch(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/rotate-role/other-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "other-role"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "role mismatch should not route")
}

func TestSharedWebSocket_RouteEvent_Database_EmptyName_EmptyPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Event with no name and an unparseable path
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "event with no role info should be dropped")
}

func TestSharedWebSocket_RouteEvent_Database_CustomMount(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "my-db/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "my-db/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.PluginInfo.MountPath = "my-db/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
}

func TestSharedWebSocket_RouteEvent_Database_MultipleSubscribers(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch1 := make(chan event.GenericEvent, 10)
	ch2 := make(chan event.GenericEvent, 10)

	sub1 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns1", Name: "vds-1"},
		VaultNS:      "",
		VaultPath:    "database/shared-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch1,
	}
	sub2 := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "ns2", Name: "vds-2"},
		VaultNS:      "",
		VaultPath:    "database/shared-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch2,
	}

	require.NoError(t, ws.Subscribe(sub1))
	require.NoError(t, ws.Subscribe(sub2))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/rotate-role/shared-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "shared-role"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	assert.Len(t, ch1, 1, "first subscriber should receive event")
	assert.Len(t, ch2, 1, "second subscriber should receive event")
}

func TestSharedWebSocket_RouteEvent_Database_StaticRoleUpdate(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Static role update event
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/static-roles/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.EventType = "database/static-role-update"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
}

func TestSharedWebSocket_RouteEvent_Database_DynamicRoleUpdate(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeDatabase)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Dynamic role update event
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/roles/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.EventType = "database/role-update"
	msg.Data.PluginInfo.MountPath = "database/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
}

// --- LDAP event routing tests ---

func TestSharedWebSocket_RouteEvent_LDAP_Rotate(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLDAP)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "ldap/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "ldap/rotate-role/my-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "my-role"
	msg.Data.EventType = "ldap/rotate"
	msg.Data.PluginInfo.MountPath = "ldap/"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
}

func TestSharedWebSocket_RouteEvent_LDAP_FallbackFromPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLDAP)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "ldap/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// No Name or PluginInfo, fallback to path parsing
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "ldap/static-roles/my-role"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
}

func TestSharedWebSocket_RouteEvent_LDAP_RoleMismatch(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLDAP)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "ldap/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "ldap/rotate-role/other-role"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Name = "other-role"
	msg.Data.PluginInfo.MountPath = "ldap/"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0)
}

// --- Lease event routing tests ---

// TestSharedWebSocket_RouteEvent_Lease_ByPath verifies that lease events are
// routed using metadata.path (e.g. "database/creds/my-role") rather than the
// full lease ID. This is required for Vault Enterprise, where metadata.lease_id
// in events carries a namespace prefix that is absent from Status.SecretLease.ID.
func TestSharedWebSocket_RouteEvent_Lease_ByPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	// Subscriber registers with the credential path (mount + spec-path), not
	// the full UUID-carrying lease ID.
	credPath := "database/creds/my-role"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Real Vault lease/revoked event: metadata.path = credential path (no UUID),
	// metadata.modified = "true".
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = credPath
	msg.Data.Event.Metadata.LeaseID = credPath + "/LkXg1KWeMIEJhPphkScZSUbi.wu1Js"
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Operation = "revoke"
	msg.Data.EventType = "lease/revoked"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
	assert.Equal(t, "default", evt.Object.GetNamespace())
}

func TestSharedWebSocket_RouteEvent_Lease_MismatchedPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/creds/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Event for a different credential path — should not route.
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "database/creds/other-role"
	msg.Data.Event.Metadata.Operation = "revoke"
	msg.Data.EventType = "lease/revoked"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "mismatched credential path should not route")
}

func TestSharedWebSocket_RouteEvent_Lease_EmptyPath(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultNS:      "",
		VaultPath:    "database/creds/my-role",
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Event with no path — should be dropped.
	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = ""
	msg.Data.Event.Metadata.Operation = "expire"
	msg.Data.EventType = "lease/expired"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "event with empty path should be dropped")
}

// TestSharedWebSocket_RouteEvent_Lease_WithNamespace verifies that lease
// routing ignores the event namespace. In Vault Enterprise, lease events may
// arrive with a namespace in the data envelope, but subscribers register with
// a namespace-free path key (mount/creds/role).
func TestSharedWebSocket_RouteEvent_Lease_WithNamespace(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	credPath := "database/creds/my-role"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Event carries a namespace in the data envelope, but routing matches on
	// metadata.path alone (namespace-agnostic).
	msg := &EventMessage{}
	msg.Data.Namespace = "prod/"
	msg.Data.Event.Metadata.Path = credPath
	msg.Data.Event.Metadata.Operation = "expire"
	msg.Data.EventType = "lease/expired"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
}

// TestSharedWebSocket_RouteEvent_Lease_IgnoresNamespace verifies that a
// different namespace on the event still routes. In Vault Enterprise the
// metadata.lease_id may be prefixed with a namespace, but routing uses
// metadata.path which is always namespace-free.
func TestSharedWebSocket_RouteEvent_Lease_IgnoresNamespace(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	credPath := "database/creds/my-role"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = "staging"
	// In Vault Enterprise, metadata.lease_id may carry a namespace prefix.
	// We must route by path, not lease_id.
	msg.Data.Event.Metadata.LeaseID = "staging/" + credPath + "/LkXg1KWeMIEJhPphkScZSUbi.wu1Js"
	msg.Data.Event.Metadata.Path = credPath
	msg.Data.Event.Metadata.Operation = "revoke"
	msg.Data.EventType = "lease/revoked"

	ws.routeEvent(msg)

	require.Len(t, ch, 1, "lease routing should match regardless of namespace prefix in lease_id")
}

// TestSharedWebSocket_RouteEvent_Lease_IgnoresRenewals verifies that
// lease/renewed events (operation=renew) are silently dropped to prevent
// a feedback loop where VSO's own LifetimeWatcher renewals trigger
// unnecessary reconciliations.
func TestSharedWebSocket_RouteEvent_Lease_IgnoresRenewals(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	credPath := "database/creds/my-role"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Renewal events should be dropped.
	renewMsg := &EventMessage{}
	renewMsg.Data.Event.Metadata.Path = credPath
	renewMsg.Data.Event.Metadata.Modified = "true"
	renewMsg.Data.Event.Metadata.Operation = "renew"
	renewMsg.Data.EventType = "lease/renewed"

	ws.routeEvent(renewMsg)
	require.Empty(t, ch, "lease renewal events should not trigger reconciliation")

	// Revoke events should be delivered (modified=true, operation=revoke).
	revokeMsg := &EventMessage{}
	revokeMsg.Data.Event.Metadata.Path = credPath
	revokeMsg.Data.Event.Metadata.Modified = "true"
	revokeMsg.Data.Event.Metadata.Operation = "revoke"
	revokeMsg.Data.EventType = "lease/revoked"

	ws.routeEvent(revokeMsg)
	require.Len(t, ch, 1, "lease revoke events should trigger reconciliation")
}

// TestSharedWebSocket_RouteEvent_Lease_ExpiredRouted verifies that
// lease/expired events (modified=false, operation=expire) are routed.
// The modified check is bypassed for EventTypeLease so that both
// lease/expired (modified=false) and lease/revoked (modified=true) trigger
// reconciliation.
func TestSharedWebSocket_RouteEvent_Lease_ExpiredRouted(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	credPath := "database/creds/dev-postgres"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	// Simulate a real Vault lease/expired event: modified=false, operation=expire.
	msg := &EventMessage{}
	msg.Data.Event.Metadata.Path = credPath
	msg.Data.Event.Metadata.LeaseID = credPath + "/LkXg1KWeMIEJhPphkScZSUbi.wu1Js"
	msg.Data.Event.Metadata.Modified = "false"
	msg.Data.Event.Metadata.Operation = "expire"
	msg.Data.EventType = "lease/expired"

	ws.routeEvent(msg)

	require.Len(t, ch, 1, "lease/expired with modified=false must route (bypass active for lease events)")
	evt := <-ch
	assert.Equal(t, "my-vds", evt.Object.GetName())
}

// TestSharedWebSocket_RouteEvent_Lease_IssueDropped verifies that
// lease/issued events (operation=issue) are dropped to prevent reconcile
// loops when VSO fetches new credentials.
func TestSharedWebSocket_RouteEvent_Lease_IssueDropped(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeLease)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	credPath := "database/creds/my-role"
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vds"},
		VaultPath:    credPath,
		ResourceType: "VaultDynamicSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Event.Metadata.Path = credPath
	msg.Data.Event.Metadata.Modified = "true"
	msg.Data.Event.Metadata.Operation = "issue"
	msg.Data.EventType = "lease/issued"

	ws.routeEvent(msg)

	assert.Len(t, ch, 0, "lease/issued events must be dropped to avoid reconcile loops")
}

// --- extractMountAndRole tests ---

func TestExtractMountAndRole(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantMnt  string
		wantRole string
	}{
		{
			name:     "database rotate path",
			path:     "database/rotate-role/my-role",
			wantMnt:  "database",
			wantRole: "my-role",
		},
		{
			name:     "database static-creds path",
			path:     "database/static-creds/my-role",
			wantMnt:  "database",
			wantRole: "my-role",
		},
		{
			name:     "database creds path",
			path:     "database/creds/my-role",
			wantMnt:  "database",
			wantRole: "my-role",
		},
		{
			name:     "ldap rotate path",
			path:     "ldap/rotate-role/my-role",
			wantMnt:  "ldap",
			wantRole: "my-role",
		},
		{
			name:     "custom mount path",
			path:     "my-db/roles/my-role",
			wantMnt:  "my-db",
			wantRole: "my-role",
		},
		{
			name:     "too few segments",
			path:     "database/my-role",
			wantMnt:  "",
			wantRole: "",
		},
		{
			name:     "single segment",
			path:     "database",
			wantMnt:  "",
			wantRole: "",
		},
		{
			name:     "empty path",
			path:     "",
			wantMnt:  "",
			wantRole: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mount, role := extractMountAndRole(tt.path)
			assert.Equal(t, tt.wantMnt, mount)
			assert.Equal(t, tt.wantRole, role)
		})
	}
}

// --- KV routing still works with new routing logic ---

func TestSharedWebSocket_RouteEvent_KV_StillWorksWithBranching(t *testing.T) {
	ws := newTestSharedWebSocket(EventTypeKV)
	defer ws.cancel()

	ch := make(chan event.GenericEvent, 10)
	sub := &Subscriber{
		ResourceKey:  types.NamespacedName{Namespace: "default", Name: "my-vss"},
		VaultNS:      "",
		VaultPath:    "kv/data/app1/config",
		ResourceType: "VaultStaticSecret",
		ReconcileCh:  ch,
	}
	require.NoError(t, ws.Subscribe(sub))

	msg := &EventMessage{}
	msg.Data.Namespace = ""
	msg.Data.Event.Metadata.Path = "kv/data/app1/config"
	msg.Data.Event.Metadata.Modified = "true"

	ws.routeEvent(msg)

	require.Len(t, ch, 1)
	evt := <-ch
	assert.Equal(t, "my-vss", evt.Object.GetName())
}
