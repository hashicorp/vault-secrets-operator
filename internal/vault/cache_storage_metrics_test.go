// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func Test_clientCacheStorageCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	ctx := context.Background()
	clientBuilder := fake.NewClientBuilder()
	tests := []struct {
		name           string
		client         ctrlclient.Client
		errorClient    ctrlclient.Client
		expectedLength float64
		createEntries  int
	}{
		{
			name:           "length-zero",
			client:         clientBuilder.Build(),
			expectedLength: 0,
		},
		{
			name:           "length-five",
			client:         clientBuilder.Build(),
			expectedLength: 5,
			createEntries:  5,
		},
		{
			name:   "length-negative-one",
			client: clientBuilder.Build(),
			// scheme-less client to be used where we want the clientCacheStorageCollector()
			// to encounter an clientCacheStorage error.
			errorClient:    clientBuilder.WithScheme(runtime.NewScheme()).Build(),
			expectedLength: -1,
			createEntries:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NewDefaultClientCacheStorage always requires a ctrlclient.Client that has the core scheme.
			storage, err := NewDefaultClientCacheStorage(ctx, tt.client, nil, nil)
			require.NoError(t, err)

			client := tt.client
			if tt.errorClient != nil {
				// in this case we want the Collector's client to produce an error when calling storage.Len(). The expectedLength should be -1,
				// denoting an error was encountered during the metrics collection.
				client = tt.errorClient
			}

			collector := newClientCacheStorageCollector(storage, ctx, client)
			reg.MustRegister(collector)

			t.Cleanup(func() {
				reg.Unregister(collector)
			})

			for i := 0; i < int(tt.expectedLength); i++ {
				req := ClientCacheStorageStoreRequest{
					Client: &defaultClient{
						authObj: &secretsv1alpha1.VaultAuth{
							ObjectMeta: metav1.ObjectMeta{
								Name:       fmt.Sprintf("auth-%d", i),
								UID:        types.UID(uuid.New().String()),
								Generation: 0,
							},
							Spec: secretsv1alpha1.VaultAuthSpec{
								Method: "kubernetes",
							},
						},
						connObj: &secretsv1alpha1.VaultConnection{
							ObjectMeta: metav1.ObjectMeta{
								Name:       fmt.Sprintf("conn-%d", i),
								UID:        types.UID(uuid.New().String()),
								Generation: 0,
							},
						},
						credentialProvider: &kubernetesCredentialProvider{
							uid: types.UID(uuid.New().String()),
						},
					},
				}
				_, err = storage.Store(ctx, tt.client, req)
				require.NoError(t, err)
			}

			mfs, err := reg.Gather()
			require.NoError(t, err)

			assert.Len(t, mfs, 1)
			for _, mf := range mfs {
				m := mf.GetMetric()
				switch name := mf.GetName(); name {
				case metricsFQNClientCacheStorageLength:
					assert.Equal(t, tt.expectedLength, *m[0].Gauge.Value)
				default:
					assert.Fail(t, "missing a test for metric %s", name)
				}
			}
		})
	}
}
