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

// ClientCache provides an interface for Cacheing a Client.
type ClientCache interface {
	Get(string) (Client, bool)
	Add(Client) (bool, error)
	Remove(string) bool
	Len() int
	Prune(filterFunc ClientCachePruneFilterFunc) []string
}

type ObjectKeyCache interface {
	Add(ctrlclient.ObjectKey, string) bool
	Get(ctrlclient.ObjectKey) (string, bool)
	Remove(ctrlclient.ObjectKey) bool
}

var _ ObjectKeyCache = (*objectKeyCache)(nil)

type objectKeyCache struct {
	// ObjectKey cache mapping a client.ObjectKey to Client cache key.
	// Used for detecting cache key changes between calls to GetClient
	cache *lru.Cache
}

func (o objectKeyCache) Add(key ctrlclient.ObjectKey, cacheKey string) bool {
	return o.cache.Add(key, cacheKey)
}

func (o objectKeyCache) Get(key ctrlclient.ObjectKey) (string, bool) {
	if v, ok := o.cache.Get(key); ok {
		return v.(string), ok
	}

	return "", false
}

func (o objectKeyCache) Remove(key ctrlclient.ObjectKey) bool {
	return o.cache.Remove(key)
}

var _ ClientCache = (*clientCache)(nil)

type clientCache struct {
	cache *lru.Cache
}

func (c *clientCache) Len() int {
	return c.cache.Len()
}

func (c *clientCache) Get(key string) (Client, bool) {
	var cacheEntry Client
	raw, ok := c.cache.Get(key)
	if ok {
		cacheEntry = raw.(Client)
	}
	return cacheEntry, ok
}

func (c *clientCache) Add(client Client) (bool, error) {
	cacheKey, err := client.GetCacheKey()
	if err != nil {
		return false, err
	}
	return c.cache.Add(cacheKey, client), nil
}

func (c *clientCache) Remove(key string) bool {
	return c.cache.Remove(key)
}

func (c *clientCache) Prune(filter ClientCachePruneFilterFunc) []string {
	var pruned []string
	for _, k := range c.cache.Keys() {
		if v, ok := c.cache.Peek(k); ok {
			if filter(v.(Client)) {
				if ok := c.cache.Remove(k); ok {
					pruned = append(pruned, k.(string))
				}
			}
		}
	}

	return pruned
}

func NewClientCache(size int) (ClientCache, error) {
	lruCache, err := lru.New(size)
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
