// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

func Test_defaultClientCacheStorage_Purge(t *testing.T) {
	ctx := context.Background()

	builder := fake.NewClientBuilder()
	tests := []struct {
		name    string
		config  *ClientCacheStorageConfig
		create  int
		client  ctrlclient.Client
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "zero",
			config:  DefaultClientCacheStorageConfig(),
			create:  0,
			client:  builder.Build(),
			wantErr: assert.NoError,
		},
		{
			name:    "five",
			config:  DefaultClientCacheStorageConfig(),
			create:  5,
			client:  builder.Build(),
			wantErr: assert.NoError,
		},
		{
			// use an empty runtime.Scheme to induce an error on corev1.Secret creation, etc.
			name: "error-empty-scheme",
			config: &ClientCacheStorageConfig{
				skipHMACSecret: true,
			},
			client: builder.WithScheme(&runtime.Scheme{}).Build(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`no kind is registered for the type v1.Secret in scheme ""`, i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := newDefaultClientCacheStorage(ctx, tt.client, tt.config, nil)
			require.NoError(t, err)

			for i := 0; i < tt.create; i++ {
				o := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("entry-%d", i),
						Namespace: common.OperatorNamespace,
						Labels:    commonMatchingLabels,
					},
				}
				require.NoError(t, tt.client.Create(ctx, o))
			}

			if tt.create > 0 {
				// check secrets list secrets before purge
				assertCacheSecretLen(t, ctx, tt.client, tt.create)
			}

			err = c.Purge(ctx, tt.client)
			if !tt.wantErr(t, err, fmt.Sprintf("Purge(%v, %v)", ctx, tt.client)) || err != nil {
				return
			}

			// check secrets list secrets after purge
			assertCacheSecretLen(t, ctx, tt.client, 0, "Purge(%v, %v)", ctx, tt.client)

			// ensure that the purge did not delete the secret holding the HMAC key that is
			// created in NewDefaultClientCacheStorage()
			var f corev1.SecretList
			require.NoError(t, tt.client.List(ctx, &f, ctrlclient.InNamespace(common.OperatorNamespace)))
			require.Len(t, f.Items, 1)

			hmacSecret := f.Items[0]
			assert.Equal(t,
				tt.config.HMACSecretObjKey,
				ctrlclient.ObjectKey{
					Namespace: hmacSecret.GetNamespace(),
					Name:      hmacSecret.GetName(),
				})
		})
	}
}

func Test_defaultClientCacheStorage_RestoreAll(t *testing.T) {
	ctx := context.Background()
	sec := &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken: "baz",
		},
	}

	secretData, err := json.Marshal(sec)
	require.NoError(t, err)

	builder := fake.NewClientBuilder()
	tests := []struct {
		name       string
		config     *ClientCacheStorageConfig
		create     int
		req        ClientCacheStorageRestoreAllRequest
		client     ctrlclient.Client
		secretData []byte
		messageMAC []byte
		want       []*clientCacheStorageEntry
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name:    "none",
			config:  DefaultClientCacheStorageConfig(),
			client:  builder.Build(),
			wantErr: assert.NoError,
		},
		{
			name:       "one",
			config:     DefaultClientCacheStorageConfig(),
			client:     builder.Build(),
			create:     1,
			secretData: secretData,
			want: []*clientCacheStorageEntry{
				{
					CacheKey:    "entry-0",
					VaultSecret: sec,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:       "three",
			config:     DefaultClientCacheStorageConfig(),
			client:     builder.Build(),
			create:     3,
			secretData: secretData,
			want: []*clientCacheStorageEntry{
				{
					CacheKey:    "entry-0",
					VaultSecret: sec,
				},
				{
					CacheKey:    "entry-1",
					VaultSecret: sec,
				},
				{
					CacheKey:    "entry-2",
					VaultSecret: sec,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "invalid-missing-required-data",
			create: 1,
			config: DefaultClientCacheStorageConfig(),
			client: builder.Build(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf(`secret data for %q missing required fields: %v`,
						ctrlclient.ObjectKey{Namespace: common.OperatorNamespace, Name: "entry-0"},
						[]string{fieldCachedSecret, fieldMACMessage}), i...)
			},
		},
		{
			name:       "invalid-message-MAC",
			create:     1,
			config:     DefaultClientCacheStorageConfig(),
			messageMAC: []byte(`bogus`),
			secretData: secretData,
			client:     builder.Build(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf("invalid message MAC for secret %q",
						ctrlclient.ObjectKey{Namespace: common.OperatorNamespace, Name: "entry-0"}),
					i...)
			},
		},
		{
			name:       "invalid-message-MAC-no-prune-on-error",
			create:     1,
			config:     DefaultClientCacheStorageConfig(),
			messageMAC: []byte(`bogus`),
			secretData: secretData,
			client:     builder.Build(),
			req: ClientCacheStorageRestoreAllRequest{
				NoPruneOnError: true,
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf("invalid message MAC for secret %q",
						ctrlclient.ObjectKey{Namespace: common.OperatorNamespace, Name: "entry-0"}),
					i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := newDefaultClientCacheStorage(ctx, tt.client, tt.config, nil)
			require.NoError(t, err)

			if tt.create > 0 {
				for i := 0; i < tt.create; i++ {
					name := fmt.Sprintf("entry-%d", i)
					labels := maps.Clone(commonMatchingLabels)
					labels[labelCacheKey] = name
					o := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      name,
							Namespace: common.OperatorNamespace,
							Labels:    labels,
						},
					}
					o.ObjectMeta.Labels[labelCacheKey] = o.ObjectMeta.Name
					if tt.secretData != nil {
						message, err := c.message(name, name, tt.secretData)
						require.NoError(t, err)
						messageMAC := tt.messageMAC
						if messageMAC == nil {
							messageMAC, err = helpers.MACMessage(c.hmacKey, message)
							if err != nil {
								require.NoError(t, err)
							}
						}
						o.Data = map[string][]byte{
							fieldCachedSecret: tt.secretData,
							fieldMACMessage:   messageMAC,
						}
					}
					require.NoError(t, tt.client.Create(ctx, o))
				}
				// check secrets list secrets before purge
				assertCacheSecretLen(t, ctx, tt.client, tt.create)
			}

			got, err := c.RestoreAll(ctx, tt.client, tt.req)
			if !tt.wantErr(t, err, fmt.Sprintf("RestoreAll(%v, %v, %v)", ctx, tt.client, tt.req)) {
				return
			}

			assert.Equalf(t, tt.want, got, "RestoreAll(%v, %v, %v)", ctx, tt.client, tt.req)

			expectedLen := tt.create
			if err != nil {
				if tt.req.NoPruneOnError {
					expectedLen = tt.create
				} else {
					expectedLen = 0
				}
			}

			assertCacheSecretLen(t, ctx, tt.client, expectedLen,
				"RestoreAll(%v, %v, %v)", ctx, tt.client, tt.req)
		})
	}
}

func assertCacheSecretLen(t *testing.T, ctx context.Context, client ctrlclient.Client, length int, i ...any) bool {
	t.Helper()

	listOptions := []ctrlclient.ListOption{
		commonMatchingLabels,
		ctrlclient.InNamespace(common.OperatorNamespace),
	}

	var so corev1.SecretList
	require.NoError(t, client.List(ctx, &so, listOptions...))
	return assert.Len(t, so.Items, length, i...)
}
