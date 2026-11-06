// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	vsoconsts "github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

// readingVSSClient is a vault.Client whose Read is backed by
// MockRecordingVaultClient, which only implements ClientBase. The mock is held
// in a named field rather than embedded so that its methods do not collide
// with the embedded vault.Client interface.
type readingVSSClient struct {
	vault.Client
	mock *vault.MockRecordingVaultClient
}

func newReadingVSSClient(responses map[string][]vault.Response) *readingVSSClient {
	return &readingVSSClient{
		mock: &vault.MockRecordingVaultClient{
			ReadResponses: responses,
			CheckPaths:    true,
		},
	}
}

func (c *readingVSSClient) Read(ctx context.Context, req vault.ReadRequest) (vault.Response, error) {
	return c.mock.Read(ctx, req)
}

// requests returns the recorded Vault requests, in order.
func (c *readingVSSClient) requests() []*vault.MockRequest {
	return c.mock.Requests
}

// readPaths returns the Vault paths that were read, in order.
func (c *readingVSSClient) readPaths() []string {
	paths := make([]string, 0, len(c.mock.Requests))
	for _, req := range c.mock.Requests {
		paths = append(paths, req.Path)
	}
	return paths
}

func kvV2Resp(data, metadata map[string]any) vault.Response {
	raw := map[string]any{"data": data}
	if metadata != nil {
		raw["metadata"] = metadata
	}
	return vault.NewKVV2Response(&api.Secret{Data: raw})
}

func kvV1Resp(data map[string]any) vault.Response {
	return vault.NewKVV1Response(&api.Secret{Data: data})
}

func Test_parseSecretKeyRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		want    secretKeyRef
		wantErr string
	}{
		{
			name: "path and key",
			ref:  "apps/app1#token",
			want: secretKeyRef{Path: "apps/app1", Key: "token"},
		},
		{
			name: "path key and version",
			ref:  "infrastructure/oracle/db1/schema1#db-password#2",
			want: secretKeyRef{Path: "infrastructure/oracle/db1/schema1", Key: "db-password", Version: 2},
		},
		{
			name: "leading slash is trimmed",
			ref:  "/apps/app1#token",
			want: secretKeyRef{Path: "apps/app1", Key: "token"},
		},
		{
			name: "surrounding whitespace is trimmed",
			ref:  " apps/app1 # token # 3 ",
			want: secretKeyRef{Path: "apps/app1", Key: "token", Version: 3},
		},
		{
			name: "explicit version zero means latest",
			ref:  "apps/app1#token#0",
			want: secretKeyRef{Path: "apps/app1", Key: "token", Version: 0},
		},
		{
			name:    "no separator",
			ref:     "apps/app1",
			wantErr: `invalid secret reference "apps/app1", want SECRET_PATH#KEY[#VERSION]`,
		},
		{
			name:    "too many separators",
			ref:     "apps/app1#token#2#3",
			wantErr: `invalid secret reference "apps/app1#token#2#3", want SECRET_PATH#KEY[#VERSION]`,
		},
		{
			name:    "empty path",
			ref:     "#token",
			wantErr: `invalid secret reference "#token", path is empty`,
		},
		{
			name:    "empty key",
			ref:     "apps/app1#",
			wantErr: `invalid secret reference "apps/app1#", key is empty`,
		},
		{
			name:    "non integer version",
			ref:     "apps/app1#token#latest",
			wantErr: `invalid secret reference "apps/app1#token#latest", version "latest" is not an integer`,
		},
		{
			name:    "negative version",
			ref:     "apps/app1#token#-1",
			wantErr: `invalid secret reference "apps/app1#token#-1", version -1 is negative`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSecretKeyRef(tt.ref)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_secretKeyRef_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "apps/app1#token",
		secretKeyRef{Path: "apps/app1", Key: "token"}.String())
	assert.Equal(t, "apps/app1#token#4",
		secretKeyRef{Path: "apps/app1", Key: "token", Version: 4}.String())
}

func Test_parseSecretKeyRefs(t *testing.T) {
	t.Parallel()

	t.Run("nil when data is unset", func(t *testing.T) {
		t.Parallel()
		refs, err := parseSecretKeyRefs(secretsv1beta1.VaultStaticSecretSpec{})
		require.NoError(t, err)
		assert.Nil(t, refs)
	})

	t.Run("parses every entry", func(t *testing.T) {
		t.Parallel()
		refs, err := parseSecretKeyRefs(secretsv1beta1.VaultStaticSecretSpec{
			Data: map[string]string{
				"db-user":     "db1/schema1#db-user",
				"db-password": "db1/schema1#db-password#2",
			},
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: vsoconsts.KVSecretTypeV2,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]secretKeyRef{
			"db-user":     {Path: "db1/schema1", Key: "db-user"},
			"db-password": {Path: "db1/schema1", Key: "db-password", Version: 2},
		}, refs)
	})

	t.Run("version rejected for kv-v1", func(t *testing.T) {
		t.Parallel()
		_, err := parseSecretKeyRefs(secretsv1beta1.VaultStaticSecretSpec{
			Data: map[string]string{"token": "apps/app1#token#2"},
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: vsoconsts.KVSecretTypeV1,
			},
		})
		require.EqualError(t, err,
			`.spec.data["token"]: version is only supported for secret type kv-v2, got "kv-v1"`)
	})

	t.Run("reports the first destination key in sorted order", func(t *testing.T) {
		t.Parallel()
		// Both entries are invalid; the error must name "a" deterministically.
		for i := 0; i < 20; i++ {
			_, err := parseSecretKeyRefs(secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"z": "bogus", "a": "bogus"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2,
				},
			})
			require.ErrorContains(t, err, `.spec.data["a"]`)
		}
	})
}

func Test_validateVaultStaticSecretSpec(t *testing.T) {
	t.Parallel()

	t.Run("rejects a spec with neither path nor data", func(t *testing.T) {
		t.Parallel()
		_, err := validateVaultStaticSecretSpec(secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
			},
		})
		require.EqualError(t, err, "one of .spec.path or .spec.data must be set")
	})

	t.Run("rejects an unsupported secret type", func(t *testing.T) {
		t.Parallel()
		_, err := validateVaultStaticSecretSpec(secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: "kv-v99", Mount: "secret", Path: "app/config",
			},
		})
		require.EqualError(t, err, `unsupported secret type "kv-v99"`)
	})

	t.Run("accepts path only", func(t *testing.T) {
		t.Parallel()
		refs, err := validateVaultStaticSecretSpec(secretsv1beta1.VaultStaticSecretSpec{
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
			},
		})
		require.NoError(t, err)
		assert.Empty(t, refs)
	})

	t.Run("accepts data only", func(t *testing.T) {
		t.Parallel()
		refs, err := validateVaultStaticSecretSpec(secretsv1beta1.VaultStaticSecretSpec{
			Data: map[string]string{"token": "app1#token"},
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]secretKeyRef{
			"token": {Path: "app1", Key: "token"},
		}, refs)
	})
}

func Test_readVaultStaticSecretData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("path only is unchanged", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app/config": {
				kvV2Resp(map[string]any{"user": "u1"}, map[string]any{"version": 7}),
			},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
		}

		data, raw, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"user": "u1"}, data)
		// raw is the untouched Vault response envelope.
		assert.Equal(t, map[string]any{
			"data":     map[string]any{"user": "u1"},
			"metadata": map[string]any{"version": 7},
		}, raw)
		assert.Equal(t, []string{"secret/data/app/config"}, c.readPaths())
	})

	t.Run("data only aggregates across paths", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/db1/schema1": {
				kvV2Resp(map[string]any{"db-user": "scott", "db-password": "tiger"}, nil),
			},
			"secret/data/app1": {
				kvV2Resp(map[string]any{"token": "t0ken"}, nil),
			},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{
					"db-user":     "db1/schema1#db-user",
					"db-password": "db1/schema1#db-password",
					"token":       "app1#token",
				},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
		}

		data, raw, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{
			"db-user": "scott", "db-password": "tiger", "token": "t0ken",
		}, data)
		assert.Equal(t, map[string]any{"data": data}, raw)
		// db1/schema1 is referenced twice but read once.
		assert.Equal(t, []string{"secret/data/db1/schema1", "secret/data/app1"}, c.readPaths())
	})

	t.Run("data overlays path", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app/config": {
				kvV2Resp(map[string]any{"user": "u1", "token": "base"},
					map[string]any{"version": 7}),
			},
			"secret/data/app1": {
				kvV2Resp(map[string]any{"token": "override"}, nil),
			},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
		}

		data, raw, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"user": "u1", "token": "override"}, data)
		// The base read's metadata survives so templates can still use it.
		assert.Equal(t, map[string]any{
			"data":     map[string]any{"user": "u1", "token": "override"},
			"metadata": map[string]any{"version": 7},
		}, raw)
	})

	t.Run("kv-v1 raw is the aggregated data", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/app1": {kvV1Resp(map[string]any{"token": "t0ken"})},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV1, Mount: "secret",
				},
			},
		}

		data, raw, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"token": "t0ken"}, data)
		assert.Equal(t, data, raw)
	})

	t.Run("same path at two versions is read twice", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app1": {
				kvV2Resp(map[string]any{"token": "latest"}, nil),
				kvV2Resp(map[string]any{"token": "pinned"}, nil),
			},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{
					"a-token": "app1#token",
					"b-token": "app1#token#2",
				},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
		}

		data, _, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"a-token": "latest", "b-token": "pinned"}, data)
		assert.Len(t, c.readPaths(), 2)
	})

	t.Run("missing key fails the sync", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app1": {kvV2Resp(map[string]any{"other": "v"}, nil)},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
		}

		_, _, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.EqualError(t, err,
			`key "token" not found in Vault secret "app1" referenced by .spec.data["token"]`)
	})

	t.Run("missing path fails the sync", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "nope#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
		}

		_, _, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.ErrorContains(t, err,
			`failed to read Vault secret "nope#token" referenced by .spec.data["token"]`)
	})

	t.Run("invalid reference fails before any read", func(t *testing.T) {
		t.Parallel()
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app/config": {kvV2Resp(map[string]any{"user": "u1"}, nil)},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "missing-separator"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
		}

		_, _, err := readVaultStaticSecretData(ctx, c, o, nil)
		require.ErrorContains(t, err, `.spec.data["token"]`)
		assert.Empty(t, c.readPaths(), "must not read Vault when the spec is invalid")
	})

	t.Run("headers are propagated to every read", func(t *testing.T) {
		t.Parallel()
		headers := http.Header{vsoconsts.HeaderVaultIndex: []string{"42"}}
		c := newReadingVSSClient(map[string][]vault.Response{
			"secret/data/app/config": {kvV2Resp(map[string]any{"user": "u1"}, nil)},
			"secret/data/app1":       {kvV2Resp(map[string]any{"token": "t"}, nil)},
		})
		o := &secretsv1beta1.VaultStaticSecret{
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
		}

		_, _, err := readVaultStaticSecretData(ctx, c, o, headers)
		require.NoError(t, err)
		require.Len(t, c.requests(), 2)
		for _, req := range c.requests() {
			assert.Equal(t, headers, req.Headers)
		}
	})
}

func Test_vaultEventPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec secretsv1beta1.VaultStaticSecretSpec
		want []string
	}{
		{
			name: "kv-v2 path only",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
			want: []string{"secret/data/app/config"},
		},
		{
			name: "kv-v1 path only",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV1, Mount: "secret", Path: "app/config",
				},
			},
			want: []string{"secret/app/config"},
		},
		{
			name: "path plus deduplicated data paths",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{
					"db-user":     "db1/schema1#db-user",
					"db-password": "db1/schema1#db-password#2",
					"token":       "app1#token",
					"same":        "app/config#user",
				},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret", Path: "app/config",
				},
			},
			want: []string{
				"secret/data/app/config",
				"secret/data/app1",
				"secret/data/db1/schema1",
			},
		},
		{
			name: "data only",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
			want: []string{"secret/data/app1"},
		},
		{
			name: "unparsable entries are skipped",
			spec: secretsv1beta1.VaultStaticSecretSpec{
				Data: map[string]string{"bad": "nope", "token": "app1#token"},
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Type: vsoconsts.KVSecretTypeV2, Mount: "secret",
				},
			},
			want: []string{"secret/data/app1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "app"},
				Spec:       tt.spec,
			}
			assert.Equal(t, tt.want, vaultEventPaths(o))
		})
	}
}

func Test_aggregatedRawData(t *testing.T) {
	t.Parallel()

	data := map[string]any{"token": "t"}

	t.Run("kv-v1 returns the data", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, data, aggregatedRawData(vsoconsts.KVSecretTypeV1, nil, data))
	})

	t.Run("kv-v2 wraps the data and keeps metadata", func(t *testing.T) {
		t.Parallel()
		base := map[string]any{
			"data":     map[string]any{"token": "old"},
			"metadata": map[string]any{"version": 3},
		}
		got := aggregatedRawData(vsoconsts.KVSecretTypeV2, base, data)
		assert.Equal(t, map[string]any{
			"data":     data,
			"metadata": map[string]any{"version": 3},
		}, got)
		// The base response must not be mutated.
		assert.Equal(t, map[string]any{"token": "old"}, base["data"])
	})

	t.Run("kv-v2 without a base read", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, map[string]any{"data": data},
			aggregatedRawData(vsoconsts.KVSecretTypeV2, nil, data))
	})
}
