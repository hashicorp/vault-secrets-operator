// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"
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
					authObj: &secretsv1beta1.VaultAuth{
						ObjectMeta: metav1.ObjectMeta{
							Name:       fmt.Sprintf("auth-%d", i),
							UID:        types.UID(uuid.New().String()),
							Generation: 0,
						},
						Spec: secretsv1beta1.VaultAuthSpec{
							Method: "kubernetes",
						},
					},
					connObj: &secretsv1beta1.VaultConnection{
						ObjectMeta: metav1.ObjectMeta{
							Name:       fmt.Sprintf("conn-%d", i),
							UID:        types.UID(uuid.New().String()),
							Generation: 0,
						},
					},
					credentialProvider: vault.NewKubernetesCredentialProvider(nil, "",
						types.UID(uuid.New().String())),
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
		name              string
		size              int
		clientCount       int
		withClones        bool
		missCount         int
		expectHits        float64
		expectEvicts      float64
		expectMisses      float64
		expectCloneHits   float64
		expectCloneEvicts float64
		expectCloneMisses float64
	}{
		{
			name:         "without-evictions",
			clientCount:  10,
			size:         10,
			expectHits:   10,
			expectMisses: 0,
			expectEvicts: 0,
		},
		{
			name:            "without-evictions-and-clones",
			clientCount:     10,
			withClones:      true,
			size:            10,
			expectHits:      10,
			expectMisses:    0,
			expectEvicts:    0,
			expectCloneHits: 10,
		},
		{
			name:         "with-evictions",
			clientCount:  10,
			size:         5,
			expectHits:   5,
			expectMisses: 5,
			expectEvicts: 5,
		},
		{
			name:         "misses-without-evictions",
			clientCount:  10,
			missCount:    6,
			size:         10,
			expectHits:   10,
			expectMisses: 6,
			expectEvicts: 0,
		},
		{
			name:         "misses-with-evictions",
			clientCount:  10,
			missCount:    3,
			size:         5,
			expectHits:   5,
			expectMisses: 8,
			expectEvicts: 5,
		},
		{
			name:            "misses-with-evictions-and-clones",
			clientCount:     10,
			withClones:      true,
			missCount:       3,
			size:            5,
			expectHits:      5,
			expectMisses:    8,
			expectEvicts:    5,
			expectCloneHits: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			cache, err := NewClientCache(tt.size, nil, reg)
			require.NoError(t, err)

			require.Greater(t, tt.clientCount, 0, "test parameter 'clientCount' must be greater than zero")

			var cacheKeys []ClientCacheKey
			var cacheCloneKeys []ClientCacheKey
			for i := 0; i < tt.clientCount; i++ {
				client, err := api.NewClient(api.DefaultConfig())
				require.NoError(t, err)
				c := &defaultClient{
					client: client,
					authObj: &secretsv1beta1.VaultAuth{
						ObjectMeta: metav1.ObjectMeta{
							Name:       fmt.Sprintf("auth-%d", i),
							UID:        types.UID(uuid.New().String()),
							Generation: 0,
						},
						Spec: secretsv1beta1.VaultAuthSpec{
							Method: consts.ProviderMethodKubernetes,
						},
					},
					connObj: &secretsv1beta1.VaultConnection{
						ObjectMeta: metav1.ObjectMeta{
							Name:       fmt.Sprintf("conn-%d", i),
							UID:        types.UID(uuid.New().String()),
							Generation: 0,
						},
					},
					credentialProvider: vault.NewKubernetesCredentialProvider(nil, "",
						types.UID(uuid.New().String())),
				}

				cacheKey, err := c.GetCacheKey()
				require.NoError(t, err)
				cacheKeys = append(cacheKeys, cacheKey)
				_, err = cache.Add(c)
				require.NoError(t, err)

				if tt.withClones {
					clone, err := c.Clone(fmt.Sprintf("ns-%d", i))
					require.NoError(t, err)
					cacheKey, err := clone.GetCacheKey()
					require.NoError(t, err)
					cacheCloneKeys = append(cacheCloneKeys, cacheKey)
					_, err = cache.Add(clone)
					require.NoError(t, err)
				}
			}

			// tt.missCount is used to increment the cache's missCounter,
			// so we use a random CacheKey to ensure that we increment the counter.
			for i := 0; i < tt.missCount; i++ {
				cacheKey := ClientCacheKey(uuid.New().String())
				_, ok := cache.Get(cacheKey)
				assert.False(t, ok,
					"found Client in cache for synthetic key %s", cacheKey)
			}

			var cacheKeysEvicted []ClientCacheKey
			if tt.size < tt.clientCount {
				// in this test, the LRU cache is FIFO, so the first cache keys added above should have been evicted
				// once we hit the LRU size limit.
				cacheKeysEvicted = cacheKeys[0:tt.size]
				cacheKeys = cacheKeys[tt.clientCount-tt.size:]
				if tt.withClones {
					cacheCloneKeys = cacheCloneKeys[tt.clientCount-tt.size:]
				}
			}
			assert.Len(t, cacheKeysEvicted, int(tt.expectEvicts),
				"test parameter 'expectEvicts' does not equal the number of synthesized client evictions")

			for _, cacheKey := range cacheKeys {
				_, ok := cache.Get(cacheKey)
				assert.True(t, ok,
					"expected Client not found in cache for key %s", cacheKey)
			}

			for _, cacheKey := range cacheCloneKeys {
				_, ok := cache.Get(cacheKey)
				assert.True(t, ok,
					"expected Client clone not found in cache for key %s", cacheKey)
			}

			for _, cacheKey := range cacheKeysEvicted {
				_, ok := cache.Get(cacheKey)
				assert.False(t, ok,
					"evicted Client found in cache for key %s", cacheKey)
			}

			assertGatheredMetrics := func() {
				mfs, err := reg.Gather()
				require.NoError(t, err)
				assert.Len(t, mfs, 6)
				for _, mf := range mfs {
					m := mf.GetMetric()
					require.Len(t, m, 1)
					msgFmt := "unexpected metric value for %s"
					switch name := mf.GetName(); name {
					case metricsFQNClientCacheEvictions:
						assert.Equal(t, tt.expectEvicts, *m[0].Gauge.Value, msgFmt, name)
					case metricsFQNClientCacheHits:
						assert.Equal(t, tt.expectHits, *m[0].Counter.Value, msgFmt, name)
					case metricsFQNClientCacheMisses:
						assert.Equal(t, tt.expectMisses, *m[0].Counter.Value, msgFmt, name)
					case metricsFQNClientCloneCacheEvictions:
						assert.Equal(t, tt.expectCloneEvicts, *m[0].Gauge.Value, msgFmt, name)
					case metricsFQNClientCloneCacheHits:
						assert.Equal(t, tt.expectCloneHits, *m[0].Counter.Value, msgFmt, name)
					case metricsFQNClientCloneCacheMisses:
						assert.Equal(t, tt.expectCloneMisses, *m[0].Counter.Value, msgFmt, name)
					default:
						assert.Fail(t, "missing a test for metric %s", name)
					}
				}
			}
			assertGatheredMetrics()

			if tt.expectEvicts > 0 {
				// test that the evictsGauge is set to 0 whenever the length of the cache
				// returns below its eviction size. So, first remove a Client from the cache,
				// and then add it back. The gauge's value should be set to 0.
				cacheKey := cacheKeys[0]
				client, ok := cache.Get(cacheKey)
				assert.True(t, ok, "expected key %s not in cache", cacheKey)
				// remove a Client from the cache for cacheKey
				assert.True(t, cache.Remove(cacheKey), "expected cache key %s in cache", cacheKey)
				evicted, err := cache.Add(client)
				require.NoError(t, err)
				require.False(t, evicted)

				// increment to expectHits to account for the call to cache.Get() above.
				tt.expectHits++
				// set expectEvicts to 0, then test the gather.
				tt.expectEvicts = 0
				assertGatheredMetrics()
			}
		})
	}
}
