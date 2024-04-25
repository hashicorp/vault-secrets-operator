// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
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
