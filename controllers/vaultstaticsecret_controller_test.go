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
