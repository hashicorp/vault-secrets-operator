// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/golang-lru"
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
	cache *lru.Cache
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
		cacheEntry = v.(Client)
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
	return c.cache.Add(cacheKey, client), nil
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
// An error will be returned if the cache could not be initialized.
func NewClientCache(size int, callbackFunc onEvictCallbackFunc) (ClientCache, error) {
	lruCache, err := lru.NewWithEvict(size, callbackFunc)
	if err != nil {
		return nil, err
	}

	return &clientCache{cache: lruCache}, nil
}
