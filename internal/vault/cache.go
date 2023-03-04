// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/hashicorp/golang-lru"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
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
}

type ObjectKeyCache interface {
	Add(ctrlclient.ObjectKey, ClientCacheKey) bool
	Get(ctrlclient.ObjectKey) (string, bool)
	Remove(ctrlclient.ObjectKey) bool
}

var _ ObjectKeyCache = (*objectKeyCache)(nil)

// objectKeyCache implements ObjectKeyCache with an underlying LRU cache. The cache size is fixed.
type objectKeyCache struct {
	// ObjectKey cache mapping a client.ObjectKey to Client cache key.
	// Used for detecting cache key changes between calls to GetClient
	cache *lru.Cache
}

func (o objectKeyCache) Add(key ctrlclient.ObjectKey, cacheKey ClientCacheKey) bool {
	return o.cache.Add(key, cacheKey)
}

func (o objectKeyCache) Get(key ctrlclient.ObjectKey) (string, bool) {
	if v, ok := o.cache.Get(key); ok {
		return v.(string), ok
	}

	return "", false
}

func (o objectKeyCache) Remove(key ctrlclient.ObjectKey) bool {
	if v, ok := o.cache.Peek(key); ok {
		v.(Client).Close()
	}
	return o.cache.Remove(key)
}

var _ ClientCache = (*clientCache)(nil)

// clientCache implements ClientCache with an underlying LRU cache. The cache size is fixed.
type clientCache struct {
	cache *lru.Cache
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

func NewObjectKeyCache(size int) (ObjectKeyCache, error) {
	lruCache, err := lru.New(size)
	if err != nil {
		return nil, err
	}

	return &objectKeyCache{cache: lruCache}, nil
}
