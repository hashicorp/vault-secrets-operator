// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"strings"

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
	cache              *lru.Cache
	cloneCache         *lru.Cache
	evictionGauge      prometheus.Gauge
	hitCounter         prometheus.Counter
	missCounter        prometheus.Counter
	evictionCloneGauge prometheus.Gauge
	hitCloneCounter    prometheus.Counter
	missCloneCounter   prometheus.Counter
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
	if key.IsClone() {
		if v, ok := c.cloneCache.Get(key); ok {
			c.hitCloneCounter.Inc()
			return v.(Client), ok
		} else {
			c.missCloneCounter.Inc()
		}
		return nil, false
	}

	if v, ok := c.cache.Get(key); ok {
		c.hitCounter.Inc()
		return v.(Client), ok
	} else {
		c.missCounter.Inc()
		return nil, false
	}
}

// Add a Client to the cache by calling Client.GetCacheKey().
// This is the key that can be used access it in the future.
func (c *clientCache) Add(client Client) (bool, error) {
	cacheKey, err := client.GetCacheKey()
	if err != nil {
		return false, err
	}

	if client.IsClone() {
		if !cacheKey.IsClone() {
			return false, fmt.Errorf("invalid cacheKey for cloned client %q", cacheKey)
		}
		evicted := c.cloneCache.Add(cacheKey, client)
		if evicted {
			c.evictionCloneGauge.Inc()
		} else {
			c.evictionCloneGauge.Set(0)
		}

		return evicted, nil
	} else {
		evicted := c.cache.Add(cacheKey, client)
		if evicted {
			c.evictionGauge.Inc()
		} else {
			c.evictionGauge.Set(0)
		}

		return evicted, nil
	}
}

// Remove a Client from the cache. The key can be had by calling Client.GetCacheKey(), or
// by computing it from computeClientCacheKey().
// Returns true if the key was present in the cache.
// If it was present then Client.Close() will be called.
func (c *clientCache) Remove(key ClientCacheKey) bool {
	var removed bool
	if v, ok := c.cache.Peek(key); ok {
		client := v.(Client)
		removed = c.remove(key, client)
	}

	return removed
}

func (c *clientCache) Prune(filterFunc ClientCachePruneFilterFunc) []ClientCacheKey {
	var pruned []ClientCacheKey
	for _, k := range c.cache.Keys() {
		if v, ok := c.cache.Peek(k); ok {
			key := k.(ClientCacheKey)
			client := v.(Client)
			if filterFunc(client) {
				if c.remove(key, client) {
					pruned = append(pruned)
				}
			}
		}
	}

	return pruned
}

func (c *clientCache) remove(key ClientCacheKey, client Client) bool {
	client.Close()
	if !client.IsClone() {
		c.pruneClones(key)
	}

	return c.cache.Remove(key)
}

func (c *clientCache) pruneClones(cacheKey ClientCacheKey) {
	for _, k := range c.cloneCache.Keys() {
		if !strings.HasPrefix(k.(ClientCacheKey).String(), cacheKey.String()) {
			continue
		}

		if _, ok := c.cloneCache.Peek(k); ok {
			c.cloneCache.Remove(k)
		}
	}
}

type onEvictCallbackFunc func(key, value interface{})

func onEvictPruneClonesFunc(cache *clientCache) onEvictCallbackFunc {
	return func(key, _ interface{}) {
		cache.pruneClones(key.(ClientCacheKey))
	}
}

// NewClientCache returns a ClientCache with its onEvictCallbackFunc set.
// If metricsRegistry is not nil, then the ClientCache's metric collectors will be
// registered in that prometheus.Registry. It's up to the caller to handle
// unregistering the collectors.
// An error will be returned if the cache could not be initialized.
func NewClientCache(size int, callbackFunc onEvictCallbackFunc, metricsRegistry prometheus.Registerer) (ClientCache, error) {
	cache := &clientCache{
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
		evictionCloneGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricsFQNClientCloneCacheEvictions,
			Help: "Number of client clone cache evictions.",
		}),
		hitCloneCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricsFQNClientCloneCacheHits,
			Help: "Number of client clone cache hits.",
		}),
		missCloneCounter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricsFQNClientCloneCacheMisses,
			Help: "Number of client clone cache misses.",
		}),
	}

	onEvictFunc := func(key, value interface{}) {
		if callbackFunc != nil {
			callbackFunc(key, value)
		}
		onEvictPruneClonesFunc(cache)(key, value)
	}

	lruCache, err := lru.NewWithEvict(size, onEvictFunc)
	if err != nil {
		return nil, err
	}

	lruCloneCache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	cache.cache = lruCache
	cache.cloneCache = lruCloneCache

	if metricsRegistry != nil {
		metricsRegistry.MustRegister(
			cache.evictionGauge, cache.hitCounter, cache.missCounter,
			cache.evictionCloneGauge, cache.hitCloneCounter, cache.missCloneCounter,
		)
	}

	return cache, nil
}
