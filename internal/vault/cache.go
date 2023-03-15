// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
)

// ClientCachePruneFilterFunc allows for selective pruning of the ClientCache.
// In the case where the return value is true, the Client will be removed from the cache.
type ClientCachePruneFilterFunc func(Client) bool

// ClientCache provides an interface for Caching a Client.
type ClientCache interface {
	Get(ClientCacheKey) (Client, bool)
	Add(Client) (bool, error)
	Remove(ClientCacheKey) bool
	Len() int
	Prune(filterFunc ClientCachePruneFilterFunc) []ClientCacheKey
	Contains(key ClientCacheKey) bool
}

var _ ClientCache = (*clientCache)(nil)

// clientCache implements ClientCache with an underlying LRU cache. The cache size is fixed.
type clientCache struct {
	cache         *lru.Cache
	evictionGauge prometheus.Gauge
	hitCounter    prometheus.Counter
	missCounter   prometheus.Counter
}

func (c *clientCache) Contains(key ClientCacheKey) bool {
	return c.cache.Contains(key)
}

// Len returns the length/size of the cache.
func (c *clientCache) Len() int {
	return c.cache.Len()
}

// Get a Client for key, returning the Client, and a boolean if the key
// was found in the cache.
func (c *clientCache) Get(key ClientCacheKey) (Client, bool) {
	var cacheEntry Client
	v, ok := c.cache.Get(key)
	if ok {
		c.hitCounter.Inc()
		cacheEntry = v.(Client)
	} else {
		c.missCounter.Inc()
	}

	return cacheEntry, ok
}

// Add a Client to the cache by calling Client.GetCacheKey().
// This is the key that can be used access it in the future.
func (c *clientCache) Add(client Client) (bool, error) {
	cacheKey, err := client.GetCacheKey()
	if err != nil {
		return false, err
	}

	evicted := c.cache.Add(cacheKey, client)
	if evicted {
		c.evictionGauge.Inc()
	} else {
		c.evictionGauge.Set(0)
	}

	return evicted, nil
}

// Remove a Client from the cache. The key can be had by calling Client.GetCacheKey(). Or computing it from computeClientCacheKey()
func (c *clientCache) Remove(key ClientCacheKey) bool {
	if v, ok := c.cache.Peek(key); ok {
		v.(Client).Close()
	}

	return c.cache.Remove(key)
}

func (c *clientCache) Prune(filterFunc ClientCachePruneFilterFunc) []ClientCacheKey {
	var pruned []ClientCacheKey
	for _, k := range c.cache.Keys() {
		if v, ok := c.cache.Peek(k); ok {
			vc := v.(Client)
			if filterFunc(vc) {
				vc.Close()
				if ok := c.cache.Remove(k); ok {
					pruned = append(pruned, k.(ClientCacheKey))
				}
			}
		}
	}

	return pruned
}

type onEvictCallbackFunc func(key, value interface{})

// NewClientCache returns a ClientCache with its onEvictCallbackFunc set.
// If metricsRegistry is not nil, then the ClientCache's metric collectors will be
// registered in that prometheus.Registry. It's up to the caller to handle
// unregistering the collectors.
// An error will be returned if the cache could not be initialized.
func NewClientCache(size int, callbackFunc onEvictCallbackFunc, metricsRegistry prometheus.Registerer) (ClientCache, error) {
	lruCache, err := lru.NewWithEvict(size, callbackFunc)
	if err != nil {
		return nil, err
	}

	cache := &clientCache{
		cache: lruCache,
		evictionGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricsFQNClientCacheEvictions,
			Help: "Number of cache evictions.",
		}),
		hitCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricsFQNClientCacheHits,
			Help: "Number of cache hits.",
		}),
		missCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricsFQNClientCacheMisses,
			Help: "Number of cache misses.",
		}),
	}

	if metricsRegistry != nil {
		metricsRegistry.MustRegister(cache.evictionGauge, cache.hitCounter, cache.missCounter)
	}

	return cache, nil
}
