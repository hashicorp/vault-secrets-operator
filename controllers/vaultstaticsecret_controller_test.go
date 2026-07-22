// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	vsoconsts "github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

func Test_newKVRequest(t *testing.T) {
	vaultIndexHeader := http.Header{vsoconsts.HeaderVaultIndex: []string{"42"}}

	tests := []struct {
		name        string
		spec        secretsv1beta1.VaultStaticSecretSpec
		headers     http.Header
		wantPath    string
		wantHeaders http.Header
		wantErr     bool
	}{
		{
			name: "kv-v1 nil headers",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type:  vsoconsts.KVSecretTypeV1,
					Mount: "secret",
					Path:  "app/config",
				},
			},
			headers:     nil,
			wantPath:    "secret/app/config",
			wantHeaders: nil,
			wantErr:     false,
		},
		{
			name: "kv-v2 nil headers",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type:  vsoconsts.KVSecretTypeV2,
					Mount: "secret",
					Path:  "app/config",
				},
			},
			headers:     nil,
			wantPath:    "secret/data/app/config",
			wantHeaders: nil,
			wantErr:     false,
		},
		{
			name: "kv-v1 with X-Vault-Index header",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type:  vsoconsts.KVSecretTypeV1,
					Mount: "secret",
					Path:  "app/config",
				},
			},
			headers:     vaultIndexHeader,
			wantPath:    "secret/app/config",
			wantHeaders: vaultIndexHeader,
			wantErr:     false,
		},
		{
			name: "kv-v2 with X-Vault-Index header",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type:    vsoconsts.KVSecretTypeV2,
					Mount:   "secret",
					Path:    "app/config",
					Version: 3,
				},
			},
			headers:     vaultIndexHeader,
			wantPath:    "secret/data/app/config",
			wantHeaders: vaultIndexHeader,
			wantErr:     false,
		},
		{
			name: "unsupported type returns error",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type:  "kv-v99",
					Mount: "secret",
					Path:  "app/config",
				},
			},
			headers: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := newKVRequest(tt.spec, tt.headers)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, req)
			assert.Equal(t, tt.wantPath, req.Path())
			assert.Equal(t, tt.wantHeaders, req.Headers())
		})
	}
}

// TestVaultStaticSecretReconciler_Reconcile_vaultIndex verifies the full
// vault_index lifecycle at the Reconcile level:
//  1. A vault_index stored in pendingVaultIndex (as routeEvent() would do on an
//     instant-update event) is forwarded as X-Vault-Index on the KV read.
//  2. LoadAndDelete consumes the entry exactly once — the map is empty after
//     the reconcile.
//  3. A subsequent reconcile without a stored index sends no X-Vault-Index.
func TestVaultStaticSecretReconciler_Reconcile_vaultIndex(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	obj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "app",
			Namespace:  "default",
			UID:        types.UID("vss-app"),
			Generation: 1,
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV1,
				Mount: "secret",
				Path:  "app/config",
			},
			Destination: secretsv1beta1.Destination{
				Name:   "app",
				Create: true,
			},
		},
		Status: secretsv1beta1.VaultStaticSecretStatus{
			LastGeneration: 1,
			VaultClientMeta: secretsv1beta1.VaultClientMeta{
				CacheKey: "cache-key",
				ID:       "client-1",
			},
		},
	}

	secretClient := testutils.NewFakeClientBuilder().
		WithStatusSubresource(obj).
		WithObjects(obj).
		Build()

	vClient := &reconcileTestVaultClient{
		MockRecordingVaultClient: &vault.MockRecordingVaultClient{
			Id: "client-1",
		},
		cacheKey: "cache-key",
	}

	objKey := client.ObjectKeyFromObject(obj)

	r := &VaultStaticSecretReconciler{
		Client:                      secretClient,
		SecretsClient:               secretClient,
		ClientFactory:               &reconcileTestClientFactory{client: vClient},
		SecretDataBuilder:           helpers.NewSecretsDataBuilder(),
		Recorder:                    record.NewFakeRecorder(10),
		BackOffRegistry:             NewBackOffRegistry(),
		referenceCache:              NewResourceReferenceCache(),
		GlobalTransformationOptions: &helpers.GlobalTransformationOptions{},
		eventWatcherRegistry:        newEventWatcherRegistry(),
	}

	// ── Reconcile 1: vault_index stored → X-Vault-Index forwarded ──────────
	// Simulate what routeEvent() does when a Vault KV event arrives.
	r.pendingVaultIndex.Store(objKey, "vault-idx-99")

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
	require.NoError(t, err)

	// The KV read must have received the X-Vault-Index header.
	require.NotEmpty(t, vClient.MockRecordingVaultClient.Requests,
		"expected at least one Vault request")
	firstReq := vClient.MockRecordingVaultClient.Requests[0]
	require.NotNil(t, firstReq.Headers, "expected X-Vault-Index header on Vault read")
	assert.Equal(t, []string{"vault-idx-99"}, firstReq.Headers[vsoconsts.HeaderVaultIndex])

	// Entry must be consumed — LoadAndDelete cleared it.
	_, stillPresent := r.pendingVaultIndex.Load(objKey)
	assert.False(t, stillPresent, "pendingVaultIndex entry must be deleted after use")

	// ── Reconcile 2: no stored index → no X-Vault-Index header ─────────────
	vClient.MockRecordingVaultClient.Requests = nil

	_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
	require.NoError(t, err)

	require.NotEmpty(t, vClient.MockRecordingVaultClient.Requests)
	secondReq := vClient.MockRecordingVaultClient.Requests[0]
	if secondReq.Headers != nil {
		assert.Empty(t, secondReq.Headers[vsoconsts.HeaderVaultIndex],
			"X-Vault-Index must not be sent when no pending index is stored")
	}
}

// mockVSSClient is a minimal vault.Client stub for VaultStaticSecret
// ensureEventWatcher tests. It covers only the four methods that VSS
// ensureEventWatcher actually calls — GetWebSocket, ID, SubscribeToEvents, and
// UnsubscribeFromEvents. GetMountType is intentionally absent: VSS never resolves
// a mount type (it always subscribes to vault.EventTypeKV directly).
type mockVSSClient struct {
	vault.Client
	subscribed []vault.EventType
	seen       []vault.EventType // recorded by UnsubscribeFromEvents
	// webSocket is returned by GetWebSocket; nil simulates no live connection.
	webSocket *vault.SharedWebSocket
	// subscribeErr, when non-nil, is returned by SubscribeToEvents.
	subscribeErr error
	// onSubscribe is an optional hook called on every SubscribeToEvents call,
	// allowing tests to capture Subscriber fields such as OnStop or NewObject.
	onSubscribe func(vault.EventType, *vault.Subscriber)
}

func (m *mockVSSClient) ID() string { return "test-vss-client" }

func (m *mockVSSClient) GetWebSocket(_ vault.EventType) *vault.SharedWebSocket {
	return m.webSocket
}

func (m *mockVSSClient) SubscribeToEvents(_ context.Context, et vault.EventType, sub *vault.Subscriber) error {
	m.subscribed = append(m.subscribed, et)
	if m.onSubscribe != nil {
		m.onSubscribe(et, sub)
	}
	return m.subscribeErr
}

func (m *mockVSSClient) UnsubscribeFromEvents(et vault.EventType, _ vault.SubscriptionKey, _ string) error {
	m.seen = append(m.seen, et)
	return nil
}

// Test_VSS_ensureEventWatcher_FreshSubscribe verifies that when no registry entry
// exists the watcher subscribes to KV events and registers metadata.
func Test_VSS_ensureEventWatcher_FreshSubscribe(t *testing.T) {
	t.Parallel()
	ch := make(chan event.GenericEvent, 10)
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
		SourceCh:             ch,
		Recorder:             record.NewFakeRecorder(10),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", Generation: 1},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV2,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}
	key := client.ObjectKeyFromObject(o)

	m := &mockVSSClient{} // webSocket == nil; no registry entry
	err := r.ensureEventWatcher(context.Background(), o, m)

	require.NoError(t, err)
	require.Contains(t, m.subscribed, vault.EventTypeKV, "must subscribe to KV events on first call")

	meta, ok := r.eventWatcherRegistry.Get(key)
	require.True(t, ok, "registry must have entry after subscribe")
	assert.Equal(t, "test-vss-client", meta.LastClientID)
	assert.Equal(t, int64(1), meta.LastGeneration)
}

// Test_VSS_ensureEventWatcher_OrphanedEntry_NilWebSocket verifies that when the
// registry has a matching entry but GetWebSocket returns nil (e.g. after an
// operator restart), ensureEventWatcher detects the orphaned entry, clears it,
// and re-subscribes rather than returning nil early.
func Test_VSS_ensureEventWatcher_OrphanedEntry_NilWebSocket(t *testing.T) {
	t.Parallel()
	ch := make(chan event.GenericEvent, 10)
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
		SourceCh:             ch,
		Recorder:             record.NewFakeRecorder(10),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kv-secret", Generation: 1},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV1,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}
	key := client.ObjectKeyFromObject(o)

	// Pre-populate registry with fully-matching metadata — the only thing that
	// should trigger re-subscribe is the nil WebSocket (orphaned entry).
	r.eventWatcherRegistry.Register(key, &eventWatcherMeta{
		LastClientID:   "test-vss-client",
		LastGeneration: 1,
	})

	// GetWebSocket returns nil — simulates operator restart with no live WebSocket.
	m := &mockVSSClient{webSocket: nil}
	err := r.ensureEventWatcher(context.Background(), o, m)

	require.NoError(t, err)
	assert.Contains(t, m.subscribed, vault.EventTypeKV,
		"must re-subscribe when WebSocket is nil (orphaned entry)")

	// Registry must be refreshed after re-subscription.
	meta, ok := r.eventWatcherRegistry.Get(key)
	require.True(t, ok, "registry must have entry after re-subscription")
	assert.Equal(t, "test-vss-client", meta.LastClientID)
}

// Test_VSS_ensureEventWatcher_OnStop_CleansRegistry verifies that the OnStop
// callback set on the VSS Subscriber deletes the registry entry when invoked,
// so the next reconcile falls through to re-subscribe instead of returning early
// because it sees a stale registry entry with matching metadata.
func Test_VSS_ensureEventWatcher_OnStop_CleansRegistry(t *testing.T) {
	t.Parallel()
	ch := make(chan event.GenericEvent, 10)
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
		SourceCh:             ch,
		Recorder:             record.NewFakeRecorder(10),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kv-secret", Generation: 1},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV2,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}
	key := client.ObjectKeyFromObject(o)

	var capturedOnStop func()
	m := &mockVSSClient{
		onSubscribe: func(_ vault.EventType, sub *vault.Subscriber) {
			if capturedOnStop == nil && sub.OnStop != nil {
				capturedOnStop = sub.OnStop
			}
		},
	}

	err := r.ensureEventWatcher(context.Background(), o, m)
	require.NoError(t, err)

	_, ok := r.eventWatcherRegistry.Get(key)
	require.True(t, ok, "registry must have entry after ensureEventWatcher")

	// Simulate WebSocket death by invoking the captured OnStop callback.
	require.NotNil(t, capturedOnStop, "OnStop must be set on the KV subscriber")
	capturedOnStop()

	// Registry entry must be gone — next reconcile will re-subscribe.
	_, ok = r.eventWatcherRegistry.Get(key)
	assert.False(t, ok, "registry entry must be deleted after OnStop fires")
}

// Test_VSS_unWatchEvents_UnsubscribesAndClearsRegistry verifies that
// unWatchEvents calls UnsubscribeFromEvents for KV and removes the registry entry.
func Test_VSS_unWatchEvents_UnsubscribesAndClearsRegistry(t *testing.T) {
	t.Parallel()
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "kv-secret"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV1,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}
	key := client.ObjectKeyFromObject(o)
	r.eventWatcherRegistry.Register(key, &eventWatcherMeta{
		LastClientID:   "test-vss-client",
		LastGeneration: 1,
	})

	m := &mockVSSClient{}
	r.unWatchEvents(o, m)

	require.Len(t, m.seen, 1, "exactly one unsubscribe call expected (KV only)")
	assert.Equal(t, vault.EventTypeKV, m.seen[0])

	_, ok := r.eventWatcherRegistry.Get(key)
	assert.False(t, ok, "registry entry must be deleted after unWatchEvents")
}

// Test_VSS_unWatchEvents_NoOpWhenNoRegistryEntry verifies that unWatchEvents
// does nothing (no panic, no unsubscribe) when the object is not in the registry.
func Test_VSS_unWatchEvents_NoOpWhenNoRegistryEntry(t *testing.T) {
	t.Parallel()
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "unknown"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV1,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}

	m := &mockVSSClient{}
	// Must not panic and must not call UnsubscribeFromEvents.
	r.unWatchEvents(o, m)

	assert.Empty(t, m.seen, "no unsubscribe should be called when object not in registry")
}

// Test_VSS_ensureEventWatcher_SubscribeError verifies that when SubscribeToEvents
// returns an error, ensureEventWatcher propagates it and does NOT register a
// registry entry (so the next reconcile retries from scratch).
func Test_VSS_ensureEventWatcher_SubscribeError(t *testing.T) {
	t.Parallel()
	ch := make(chan event.GenericEvent, 10)
	r := &VaultStaticSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
		SourceCh:             ch,
		Recorder:             record.NewFakeRecorder(10),
	}

	o := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app", Generation: 1},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type:  vsoconsts.KVSecretTypeV1,
				Mount: "secret",
				Path:  "app/config",
			},
		},
	}
	key := client.ObjectKeyFromObject(o)

	m := &mockVSSClient{subscribeErr: fmt.Errorf("websocket dial: connection refused")}
	err := r.ensureEventWatcher(context.Background(), o, m)

	require.Error(t, err, "must propagate SubscribeToEvents error to caller")
	assert.Contains(t, err.Error(), "connection refused")

	// Registry must stay empty — no successful subscription was made.
	_, ok := r.eventWatcherRegistry.Get(key)
	assert.False(t, ok, "registry must not have an entry when subscribe failed")
}
