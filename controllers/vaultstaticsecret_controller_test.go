// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

func Test_newKVRequest(t *testing.T) {
	t.Parallel()

	const (
		mount   = "secret"
		path    = "app/config"
		version = 3
	)

	vaultIndexHeader := http.Header{consts.HeaderVaultIndex: []string{"AAAAAAAAAZk="}}

	tests := []struct {
		name        string
		spec        secretsv1beta1.VaultStaticSecretSpec
		headers     http.Header
		wantPath    string
		wantHeaders http.Header
		wantErr     bool
	}{
		// ── KV v1 ────────────────────────────────────────────────────────────────
		{
			name: "kvv1-nil-headers",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: mount,
					Path:  path,
					Type:  consts.KVSecretTypeV1,
				},
			},
			headers:     nil,
			wantPath:    "secret/app/config",
			wantHeaders: nil,
		},
		{
			name: "kvv1-with-vault-index-header",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: mount,
					Path:  path,
					Type:  consts.KVSecretTypeV1,
				},
			},
			headers:     vaultIndexHeader,
			wantPath:    "secret/app/config",
			wantHeaders: vaultIndexHeader,
		},
		// ── KV v2 ────────────────────────────────────────────────────────────────
		{
			name: "kvv2-nil-headers",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount:   mount,
					Path:    path,
					Type:    consts.KVSecretTypeV2,
					Version: 0,
				},
			},
			headers:     nil,
			wantPath:    "secret/data/app/config",
			wantHeaders: nil,
		},
		{
			name: "kvv2-with-vault-index-header",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount:   mount,
					Path:    path,
					Type:    consts.KVSecretTypeV2,
					Version: 0,
				},
			},
			headers:     vaultIndexHeader,
			wantPath:    "secret/data/app/config",
			wantHeaders: vaultIndexHeader,
		},
		{
			// Version is passed through to the query parameter; headers are
			// independent of it and must still be propagated.
			name: "kvv2-with-version-and-vault-index-header",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount:   mount,
					Path:    path,
					Type:    consts.KVSecretTypeV2,
					Version: version,
				},
			},
			headers:     vaultIndexHeader,
			wantPath:    "secret/data/app/config",
			wantHeaders: vaultIndexHeader,
		},
		// ── Error cases ──────────────────────────────────────────────────────────
		{
			name: "unsupported-type-returns-error",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: mount,
					Path:  path,
					Type:  "kv-v3",
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
				assert.Nil(t, req)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, req)

			assert.Equal(t, tt.wantPath, req.Path(), "unexpected request path")
			assert.Equal(t, tt.wantHeaders, req.Headers(), "unexpected request headers")

			// For KV v2 with a version, verify the version query parameter is present.
			if tt.spec.Type == consts.KVSecretTypeV2 && tt.spec.Version > 0 {
				vals := req.Values()
				require.NotNil(t, vals)
				assert.Equal(t, []string{"3"}, vals["version"])
			}
		})
	}
}
