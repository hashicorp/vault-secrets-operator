// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"sync"
	"testing"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Test_matchSecretEvent(t *testing.T) {
	t.Parallel()

	vssKVV2 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "team-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV2,
			},
		},
	}

	vssKVV1 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "team-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV1,
			},
		},
	}

	vds := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "example",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Namespace: "team-a",
			Mount:     "db",
			Path:      "creds/app",
		},
	}

	cfg := &InstantUpdateConfig{}
	tests := []struct {
		name      string
		obj       client.Object
		eventJSON []byte
		wantMatch bool
	}{
		{
			name: "vss-kvv2-match",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: true,
		},
		{
			name: "vss-kvv2-metadata-mismatch",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/metadata/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "vss-kvv1-match",
			obj:  vssKVV1,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/app/config",
				vssKVV1.Spec.Namespace,
			)),
			wantMatch: true,
		},
		{
			name: "vss-kvv1-mismatch",
			obj:  vssKVV1,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV1.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "vss-namespace-mismatch",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				"other-team",
			)),
			wantMatch: false,
		},
		{
			name: "not-modified",
			obj:  vds,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"false"}},"namespace":"/%s"}}`,
				"db/creds/app",
				vds.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "vds-match",
			obj:  vds,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"db/creds/app",
				vds.Spec.Namespace,
			)),
			wantMatch: true,
		},
		{
			name: "vds-path-mismatch",
			obj:  vds,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
				"db/creds/other",
				vds.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "modified-missing",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":"%s"}},"namespace":"/%s"}}`,
				"kv/data/app/config",
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
		{
			name: "missing-metadata-path",
			obj:  vssKVV2,
			eventJSON: []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"modified":"true"}},"namespace":"/%s"}}`,
				vssKVV2.Spec.Namespace,
			)),
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matched, err := cfg.matchSecretEvent(context.Background(), tt.obj, tt.eventJSON)
			require.NoError(t, err)
			require.Equal(t, tt.wantMatch, matched)
		})
	}
}

// Test_matchSecretEvent_storesVaultIndex verifies that matchSecretEvent stores
// the vault_index from the event payload into PendingVaultIndex when a match is
// found, and does not store anything in all non-matching or empty-index cases.
func Test_matchSecretEvent_storesVaultIndex(t *testing.T) {
	t.Parallel()

	vssKVV2 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "kvv2", Namespace: "default"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "ns-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV2,
			},
		},
	}
	vssKVV1 := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "kvv1", Namespace: "default"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "ns-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV1,
			},
		},
	}
	vds := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "dyndb", Namespace: "default"},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Namespace: "ns-a",
			Mount:     "db",
			Path:      "creds/app",
		},
	}

	const sampleIndex = "AAAAAAAAAZk="

	eventJSON := func(path, ns, vaultIndex string) []byte {
		if vaultIndex == "" {
			return []byte(fmt.Sprintf(
				`{"data":{"event":{"metadata":{"path":%q,"modified":"true"}},"namespace":"/%s"}}`,
				path, ns,
			))
		}
		return []byte(fmt.Sprintf(
			`{"data":{"event":{"metadata":{"path":%q,"modified":"true","vault_index":%q}},"namespace":"/%s"}}`,
			path, vaultIndex, ns,
		))
	}

	tests := []struct {
		name           string
		obj            client.Object
		eventJSON      []byte
		wantMatch      bool
		wantIndexKey   *types.NamespacedName // nil means "expect no entry stored"
		wantIndexValue string
	}{
		// ── Matching cases that should store the index ──────────────────────────
		{
			name:           "vss-kvv2-match-stores-index",
			obj:            vssKVV2,
			eventJSON:      eventJSON("kv/data/app/config", "ns-a", sampleIndex),
			wantMatch:      true,
			wantIndexKey:   &types.NamespacedName{Namespace: "default", Name: "kvv2"},
			wantIndexValue: sampleIndex,
		},
		{
			name:           "vss-kvv1-match-stores-index",
			obj:            vssKVV1,
			eventJSON:      eventJSON("kv/app/config", "ns-a", sampleIndex),
			wantMatch:      true,
			wantIndexKey:   &types.NamespacedName{Namespace: "default", Name: "kvv1"},
			wantIndexValue: sampleIndex,
		},
		{
			name:           "vds-match-stores-index",
			obj:            vds,
			eventJSON:      eventJSON("db/creds/app", "ns-a", sampleIndex),
			wantMatch:      true,
			wantIndexKey:   &types.NamespacedName{Namespace: "default", Name: "dyndb"},
			wantIndexValue: sampleIndex,
		},
		{
			// Non-base64 / opaque value must be stored and forwarded as-is;
			// no client-side validation since the token is opaque.
			name:           "opaque-non-base64-value-stored-as-is",
			obj:            vssKVV2,
			eventJSON:      eventJSON("kv/data/app/config", "ns-a", "not-valid-base64!!!"),
			wantMatch:      true,
			wantIndexKey:   &types.NamespacedName{Namespace: "default", Name: "kvv2"},
			wantIndexValue: "not-valid-base64!!!",
		},
		// ── Matching cases that must NOT store the index ─────────────────────────
		{
			name:         "match-vault-index-absent",
			obj:          vssKVV2,
			eventJSON:    eventJSON("kv/data/app/config", "ns-a", ""),
			wantMatch:    true,
			wantIndexKey: nil, // no entry expected
		},
		{
			name:         "match-vault-index-empty-string",
			obj:          vssKVV2,
			eventJSON:    []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"true","vault_index":""}},"namespace":"/ns-a"}}`),
			wantMatch:    true,
			wantIndexKey: nil,
		},
		{
			name:         "match-vault-index-whitespace-only",
			obj:          vssKVV2,
			eventJSON:    []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"true","vault_index":"   "}},"namespace":"/ns-a"}}`),
			wantMatch:    true,
			wantIndexKey: nil,
		},
		// ── Non-matching cases must never store the index ───────────────────────
		{
			name:         "path-mismatch-does-not-store",
			obj:          vssKVV2,
			eventJSON:    eventJSON("kv/data/other/secret", "ns-a", sampleIndex),
			wantMatch:    false,
			wantIndexKey: nil,
		},
		{
			name:         "namespace-mismatch-does-not-store",
			obj:          vssKVV2,
			eventJSON:    eventJSON("kv/data/app/config", "other-ns", sampleIndex),
			wantMatch:    false,
			wantIndexKey: nil,
		},
		{
			name:         "not-modified-does-not-store",
			obj:          vssKVV2,
			eventJSON:    []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"false","vault_index":"AAAAAAAAAZk="}},"namespace":"/ns-a"}}`),
			wantMatch:    false,
			wantIndexKey: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var m sync.Map
			cfg := &InstantUpdateConfig{PendingVaultIndex: &m}

			matched, err := cfg.matchSecretEvent(context.Background(), tt.obj, tt.eventJSON)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMatch, matched)

			if tt.wantIndexKey != nil {
				v, ok := m.Load(*tt.wantIndexKey)
				require.True(t, ok, "expected vault_index to be stored for key %v", *tt.wantIndexKey)
				assert.Equal(t, tt.wantIndexValue, v.(string))
			} else {
				// Ensure nothing was written into the map at all.
				count := 0
				m.Range(func(_, _ any) bool { count++; return true })
				assert.Equal(t, 0, count, "expected no entry in PendingVaultIndex map")
			}
		})
	}
}

// Test_matchSecretEvent_nilPendingVaultIndex verifies that a nil PendingVaultIndex
// does not cause a panic when vault_index is present in the event payload.
func Test_matchSecretEvent_nilPendingVaultIndex(t *testing.T) {
	t.Parallel()

	vss := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "ns-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV2,
			},
		},
	}

	cfg := &InstantUpdateConfig{PendingVaultIndex: nil}
	eventJSON := []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"true","vault_index":"AAAAAAAAAZk="}},"namespace":"/ns-a"}}`)

	matched, err := cfg.matchSecretEvent(context.Background(), vss, eventJSON)
	require.NoError(t, err)
	assert.True(t, matched, "event should still match even with nil PendingVaultIndex")
}

// Test_matchSecretEvent_lastWriteWins verifies that when two rapid events fire for
// the same object before a reconcile runs, only the second (most recent) vault_index
// survives in the map.
func Test_matchSecretEvent_lastWriteWins(t *testing.T) {
	t.Parallel()

	vss := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default"},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			Namespace: "ns-a",
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: "kv",
				Path:  "app/config",
				Type:  consts.KVSecretTypeV2,
			},
		},
	}

	var m sync.Map
	cfg := &InstantUpdateConfig{PendingVaultIndex: &m}

	firstEvent := []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"true","vault_index":"AAAAAAAAAA="}},"namespace":"/ns-a"}}`)
	secondEvent := []byte(`{"data":{"event":{"metadata":{"path":"kv/data/app/config","modified":"true","vault_index":"BBBBBBBBBBB="}},"namespace":"/ns-a"}}`)

	matched, err := cfg.matchSecretEvent(context.Background(), vss, firstEvent)
	require.NoError(t, err)
	require.True(t, matched)

	matched, err = cfg.matchSecretEvent(context.Background(), vss, secondEvent)
	require.NoError(t, err)
	require.True(t, matched)

	key := types.NamespacedName{Namespace: "default", Name: "s"}
	v, ok := m.Load(key)
	require.True(t, ok)
	assert.Equal(t, "BBBBBBBBBBB=", v.(string), "second event's vault_index should overwrite the first")
}
