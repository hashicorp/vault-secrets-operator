// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	vsoconsts "github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

func Test_newKVRequest(t *testing.T) {
	vaultIndexHeader := http.Header{consts.HeaderVaultIndex: []string{"42"}}

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
					Type:  consts.KVSecretTypeV1,
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
					Type:  consts.KVSecretTypeV2,
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
					Type:  consts.KVSecretTypeV1,
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
					Type:    consts.KVSecretTypeV2,
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
				Type:  consts.KVSecretTypeV1,
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
