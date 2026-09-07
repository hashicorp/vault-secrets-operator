// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

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
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

// TestVaultStaticSecretReconciler_Reconcile is a regression test for the
// HA-failover bug where VSO permanently stopped reconciling a VaultStaticSecret
// after a transient Vault error ("local node not active but active cluster node
// not found").
//
// Root cause: both error paths previously returned
// `ctrl.Result{RequeueAfter: horizon}, nil`. Once the RequeueAfter timer fired
// without Vault recovering, the resource fell out of the work queue permanently.
//
// Fix: return the non-nil error so controller-runtime's rate-limiter keeps the
// resource enqueued and retries indefinitely until Vault recovers.
func TestVaultStaticSecretReconciler_Reconcile(t *testing.T) {
	t.Parallel()

	vaultErr := errors.New("local node not active but active cluster node not found")

	tests := []struct {
		name string
		// factory is the ClientFactory the reconciler will use.
		factory vault.ClientFactory
		// preConditions are seeded onto the VSS status before reconciliation.
		preConditions []metav1.Condition
		// hmacEnabled, when true, enables HMAC secret data on the VSS spec.
		hmacEnabled bool
		// wantErr is the expected reconcile error (nil = success).
		wantErr error
		// wantRequeueAfter, when true, asserts result.RequeueAfter > 0.
		wantRequeueAfter bool
		// wantConditionStatus is the expected SecretSynced condition status.
		wantConditionStatus metav1.ConditionStatus
		// wantConditionReason is the expected SecretSynced condition reason.
		wantConditionReason string
	}{
		{
			// ClientFactory.Get fails — Vault auth / login unreachable during HA failover.
			// The reconciler must return the error so controller-runtime keeps the
			// resource in the rate-limiter queue for indefinite retry.
			name:                "clientFactory.Get error requeues indefinitely",
			factory:             &reconcileTestClientFactory{err: vaultErr},
			wantErr:             vaultErr,
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: "Synced",
		},
		{
			// Client.Read fails — Vault returned 500 from a non-leader node.
			// Same requirement: error must propagate so the rate-limiter retries.
			name: "client.Read error requeues indefinitely",
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{
						CheckPaths: true, // no path configured → Read returns error
					},
					cacheKey: "k8s-test",
				},
			},
			wantErr:             assert.AnError, // any non-nil error
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionFalse,
			wantConditionReason: "Synced",
		},
		{
			// Vault is healthy; VSS had a stale SecretSynced=False from a prior HA
			// failure. The reconciler must flip the condition back to True/Synced —
			// no manual spec-touch required.
			name: "successful read clears stale False condition",
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{},
					cacheKey:                 "k8s-test",
				},
			},
			preConditions: []metav1.Condition{
				{
					Type:               vsoconsts.TypeSecretSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "Synced",
					Message:            "Failed to sync the secret, err=local node not active",
					LastTransitionTime: metav1.Now(),
				},
			},
			wantErr:             nil,
			wantRequeueAfter:    false, // no RefreshAfter set → RequeueAfter=0 on success
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: "Synced",
		},
		{
			// HMAC detects no data change (doSync=false). The SecretSynced condition
			// must still be written as True/Synced to clear any stale False entry.
			// Two reconciles are needed: the first stores the HMAC MAC, the second
			// sees a matching MAC and exercises the doSync=false branch.
			name:        "HMAC no-op reconcile writes True/Synced condition",
			hmacEnabled: true,
			factory: &reconcileTestClientFactory{
				client: &reconcileTestVaultClient{
					MockRecordingVaultClient: &vault.MockRecordingVaultClient{},
					cacheKey:                 "k8s-test",
				},
			},
			wantErr:             nil,
			wantRequeueAfter:    true,
			wantConditionStatus: metav1.ConditionTrue,
			wantConditionReason: "Synced",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			// Build a minimal VaultStaticSecret: kv-v1, destination.create=true so
			// the dest-exists check is bypassed.
			obj := &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default", Generation: 1},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
						Mount: "secret",
						Path:  "myapp/config",
						Type:  "kv-v1",
					},
					Destination: secretsv1beta1.Destination{
						Name:   "dest-secret",
						Create: true,
					},
				},
			}
			if tt.hmacEnabled {
				v := true
				obj.Spec.HMACSecretData = &v
			}
			if len(tt.preConditions) > 0 {
				obj.Status.Conditions = tt.preConditions
			}

			fakeClient := testutils.NewFakeClientBuilder().
				WithStatusSubresource(obj).
				WithObjects(obj).
				Build()
			require.NoError(t, fakeClient.Status().Update(ctx, obj))

			hmacKey := client.ObjectKey{Name: "hmac-key", Namespace: "default"}
			if tt.hmacEnabled {
				_, err := helpers.CreateHMACKeySecret(ctx, fakeClient, hmacKey)
				require.NoError(t, err, "failed to create HMAC key secret")
			}

			r := &VaultStaticSecretReconciler{
				Client:                      fakeClient,
				SecretsClient:               fakeClient,
				ClientFactory:               tt.factory,
				SecretDataBuilder:           helpers.NewSecretsDataBuilder(),
				HMACValidator:               helpers.NewHMACValidator(hmacKey),
				Recorder:                    record.NewFakeRecorder(10),
				BackOffRegistry:             NewBackOffRegistry(),
				referenceCache:              NewResourceReferenceCache(),
				GlobalTransformationOptions: &helpers.GlobalTransformationOptions{},
				eventWatcherRegistry:        newEventWatcherRegistry(),
			}
			objKey := client.ObjectKeyFromObject(obj)

			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})

			if tt.hmacEnabled && err == nil {
				// First reconcile stores the MAC. Run a second reconcile with the
				// same generation so MACs match and doSync=false is exercised.
				updated := &secretsv1beta1.VaultStaticSecret{}
				require.NoError(t, fakeClient.Get(ctx, objKey, updated))
				updated.Generation = 1
				require.NoError(t, fakeClient.Update(ctx, updated))

				result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
			}

			if tt.wantErr != nil {
				if tt.wantErr == assert.AnError {
					require.Error(t, err, "expected a non-nil error to keep resource in the rate-limiter queue")
				} else {
					require.ErrorIs(t, err, tt.wantErr)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.wantRequeueAfter {
				assert.Greater(t, result.RequeueAfter.Nanoseconds(), int64(0),
					"RequeueAfter must be set so the resource is retried")
			}

			// Verify SecretSynced condition.
			final := &secretsv1beta1.VaultStaticSecret{}
			require.NoError(t, fakeClient.Get(ctx, objKey, final))
			cond := findVSSCondition(final.Status.Conditions, vsoconsts.TypeSecretSynced)
			require.NotNil(t, cond, "SecretSynced condition must be present")
			assert.Equal(t, tt.wantConditionStatus, cond.Status)
			assert.Equal(t, tt.wantConditionReason, cond.Reason)
		})
	}
}

// findVSSCondition returns the first condition with the given type, or nil.
func findVSSCondition(conditions []metav1.Condition, typ string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == typ {
			return &conditions[i]
		}
	}
	return nil
}

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
	// webSocketHealthy is returned by IsWebSocketHealthy.
	webSocketHealthy bool
	// subscribeErr, when non-nil, is returned by SubscribeToEvents.
	subscribeErr error
	// unsubscribeErr, when non-nil, is returned by UnsubscribeFromEvents.
	unsubscribeErr error
	// onSubscribe is an optional hook called on every SubscribeToEvents call,
	// allowing tests to capture Subscriber fields such as OnStop or NewObject.
	onSubscribe func(vault.EventType, *vault.Subscriber)
}

func (m *mockVSSClient) ID() string { return "test-vss-client" }

func (m *mockVSSClient) IsWebSocketHealthy(_ vault.EventType) bool {
	return m.webSocketHealthy
}

func (m *mockVSSClient) SubscribeToEvents(_ context.Context, et vault.EventType, sub *vault.Subscriber) error {
	m.subscribed = append(m.subscribed, et)
	if m.onSubscribe != nil {
		m.onSubscribe(et, sub)
	}
	return m.subscribeErr
}

func (m *mockVSSClient) UnsubscribeFromEvents(_ context.Context, et vault.EventType, _ vault.SubscriptionKey, _ string) error {
	m.seen = append(m.seen, et)
	return m.unsubscribeErr
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
// registry has a matching entry but IsWebSocketHealthy returns false (e.g. after
// an operator restart), ensureEventWatcher detects the orphaned entry, clears it,
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

	// IsWebSocketHealthy returns false — simulates operator restart with no live WebSocket.
	m := &mockVSSClient{webSocketHealthy: false}
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
	r.unWatchEvents(o, m, context.Background())

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
	r.unWatchEvents(o, m, context.Background())

	assert.Empty(t, m.seen, "no unsubscribe should be called when object not in registry")
}

// Test_VSS_unWatchEvents_UnsubscribeError verifies that when UnsubscribeFromEvents
// returns an error, unWatchEvents still removes the registry entry — the error is
// treated as "already cleaned up" and must not block cleanup.
func Test_VSS_unWatchEvents_UnsubscribeError(t *testing.T) {
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

	m := &mockVSSClient{unsubscribeErr: fmt.Errorf("websocket already closed")}
	r.unWatchEvents(o, m, context.Background())

	// UnsubscribeFromEvents was still attempted.
	require.Len(t, m.seen, 1, "exactly one unsubscribe call expected even on error")
	assert.Equal(t, vault.EventTypeKV, m.seen[0])

	// Registry entry must be removed regardless of the unsubscribe error.
	_, ok := r.eventWatcherRegistry.Get(key)
	assert.False(t, ok, "registry entry must be deleted even when UnsubscribeFromEvents errors")
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

// TestVaultStaticSecretReconciler_vaultClientCallback_BlocksOnFullSourceCh
// verifies that vaultClientCallback delivers events to ALL matching CRs even
// when SourceCh has a smaller buffer than the number of matching instances.
func TestVaultStaticSecretReconciler_vaultClientCallback_BlocksOnFullSourceCh(t *testing.T) {
	t.Parallel()

	// Key must match the cacheKeyRe pattern: [provider]-[22 hex chars].
	cacheKey := fmt.Sprintf("%s-%s", "kubernetes", "aabbccddee1122334455bb")

	// Create 6 matching VaultStaticSecret instances — more than any reasonable
	// small buffer — all sharing the same client cache key.
	const instanceCount = 6
	instances := make([]*secretsv1beta1.VaultStaticSecret, instanceCount)
	for i := range instances {
		instances[i] = &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      fmt.Sprintf("vss-%d", i),
			},
			Status: secretsv1beta1.VaultStaticSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: cacheKey,
				},
			},
		}
	}

	// SourceCh is intentionally smaller than instanceCount to force the blocking
	// send path. A buffer of 1 means only the first send completes immediately;
	// all subsequent sends must block until the consumer reads.
	sourceCh := make(chan event.GenericEvent, 1)
	fakeClient := testutils.NewFakeClient()
	r := &VaultStaticSecretReconciler{
		Client:   fakeClient,
		SourceCh: sourceCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, o := range instances {
		require.NoError(t, r.Create(ctx, o))
	}

	c := &stubVSSClient{
		cacheKey:  vault.ClientCacheKey(cacheKey),
		namespace: "default",
	}

	// Run vaultClientCallback in its own goroutine (mirrors production: it is
	// always spawned by callClientCallbacks, never called on the hot path).
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		r.vaultClientCallback(ctx, c)
	}()

	// Consume all instanceCount events from the channel. Each read unblocks the
	// next blocking send in the callback goroutine.
	received := 0
	for received < instanceCount {
		select {
		case <-sourceCh:
			received++
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out after receiving %d/%d events; blocking send did not unblock", received, instanceCount)
		}
	}

	// Callback goroutine must finish now that all sends have completed.
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("vaultClientCallback goroutine did not finish after all events were consumed")
	}

	assert.Equal(t, instanceCount, received,
		"all %d matching CRs must be reconciled even with a small SourceCh buffer", instanceCount)
}

// stubVSSClient is a minimal vault.Client stub for vaultClientCallback tests.
type stubVSSClient struct {
	vault.Client
	cacheKey  vault.ClientCacheKey
	namespace string
}

func (c *stubVSSClient) GetCacheKey() (vault.ClientCacheKey, error) { return c.cacheKey, nil }
func (c *stubVSSClient) GetCredentialProvider() provider.CredentialProviderBase {
	return &stubVSSCredentialProvider{namespace: c.namespace}
}

type stubVSSCredentialProvider struct {
	provider.CredentialProviderBase
	namespace string
}

func (p *stubVSSCredentialProvider) GetNamespace() string { return p.namespace }
