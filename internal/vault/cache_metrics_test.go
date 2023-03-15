// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func Test_clientCacheCollector_Collect(t *testing.T) {
	reg := prometheus.NewRegistry()

	tests := []struct {
		name        string
		clientCount int
		size        int
	}{
		{
			name:        "basic",
			clientCount: 10,
			size:        10,
		},
		{
			name:        "with-evictions",
			clientCount: 10,
			size:        5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewClientCache(tt.size, nil, nil)
			require.NoError(t, err)

			for i := 0; i < tt.clientCount; i++ {
				_, err := cache.Add(&defaultClient{
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
				})
				require.NoError(t, err)
			}

			collector := newClientCacheCollector(cache, tt.size)
			reg.MustRegister(collector)
			t.Cleanup(func() {
				reg.Unregister(collector)
			})

			mfs, err := reg.Gather()
			require.NoError(t, err)

			var found int
			assert.Len(t, mfs, 2)
			for _, mf := range mfs {
				name := mf.GetName()
				m := mf.GetMetric()
				require.Len(t, m, 1)
				if name == metricsFQNClientCacheLength {
					found++
					if tt.size < tt.clientCount {
						assert.Equal(t, float64(tt.size), *m[0].Gauge.Value)
					} else {
						assert.Equal(t, float64(tt.clientCount), *m[0].Gauge.Value)
					}
				}
				if name == metricsFQNClientCacheSize {
					found++
					assert.Equal(t, float64(tt.size), *m[0].Gauge.Value)
				}
			}
			require.Equal(t, len(mfs), found, "not all metrics found")
		})
	}
}

func Test_clientCache_Metrics(t *testing.T) {
	tests := []struct {
		name           string
		clientCount    int
		missCount      int
		size           int
		expectHits     float64
		expectedEvicts float64
		expectMisses   float64
	}{
		{
			name:           "basic",
			clientCount:    10,
			size:           10,
			expectHits:     10,
			expectMisses:   0,
			expectedEvicts: 0,
		},
		{
			name:           "with-evictions",
			clientCount:    10,
			size:           5,
			expectHits:     5,
			expectMisses:   5,
			expectedEvicts: 5,
		},
		{
			name:           "misses-without-evictions",
			clientCount:    10,
			missCount:      6,
			size:           10,
			expectHits:     10,
			expectMisses:   6,
			expectedEvicts: 0,
		},
		{
			name:           "misses-with-evictions",
			clientCount:    10,
			missCount:      3,
			size:           5,
			expectHits:     5,
			expectMisses:   8,
			expectedEvicts: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			cache, err := NewClientCache(tt.size, nil, reg)
			require.NoError(t, err)

			var cacheKeys []ClientCacheKey
			for i := 0; i < tt.clientCount; i++ {
				c := &defaultClient{
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
				}

				cacheKey, err := c.GetCacheKey()
				require.NoError(t, err)
				cacheKeys = append(cacheKeys, cacheKey)
				_, err = cache.Add(c)
				require.NoError(t, err)
			}

			for i := 0; i < tt.missCount; i++ {
				cacheKey := ClientCacheKey(uuid.New().String())
				_, ok := cache.Get(cacheKey)
				assert.False(t, ok,
					"found Client in cache for synthetic key %s", cacheKey)
			}

			var cacheKeysEvicted []ClientCacheKey
			if tt.size < tt.clientCount {
				cacheKeysEvicted = cacheKeys[0:tt.size]
				cacheKeys = cacheKeys[tt.clientCount-tt.size:]
			}
			assert.Len(t, cacheKeysEvicted, int(tt.expectedEvicts),
				"invalid test parameters for cache evictions")

			for _, cacheKey := range cacheKeys {
				_, ok := cache.Get(cacheKey)
				assert.True(t, ok,
					"expected Client not found in cache for key %s", cacheKey)
			}

			for _, cacheKey := range cacheKeysEvicted {
				_, ok := cache.Get(cacheKey)
				assert.False(t, ok,
					"evicted Client found in cache for key %s", cacheKey)
			}

			mfs, err := reg.Gather()
			require.NoError(t, err)
			assert.Len(t, mfs, 3)
			for _, mf := range mfs {
				m := mf.GetMetric()
				require.Len(t, m, 1)
				msgFmt := "unexpected metric value for %s"
				switch name := mf.GetName(); name {
				case metricsFQNClientCacheEvictions:
					assert.Equal(t, tt.expectedEvicts, *m[0].Gauge.Value, msgFmt, name)
				case metricsFQNClientCacheHits:
					assert.Equal(t, tt.expectHits, *m[0].Counter.Value, msgFmt, name)
				case metricsFQNClientCacheMisses:
					assert.Equal(t, tt.expectMisses, *m[0].Counter.Value, msgFmt, name)
				default:
					assert.Fail(t, "missing a test for metric %s", name)
				}
			}
		})
	}
}
