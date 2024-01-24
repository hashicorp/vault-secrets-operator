// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ResourceKind string

// SecretTransformation maps to SecretTransformation custom resource.
const SecretTransformation ResourceKind = "SecretTransformation"

type ResourceReferenceCache interface {
	Add(ResourceKind, client.ObjectKey, ...client.ObjectKey)
	Get(ResourceKind, client.ObjectKey) ([]client.ObjectKey, bool)
	Remove(ResourceKind, client.ObjectKey) bool
	Prune(ResourceKind, client.ObjectKey) int
}

func NewResourceReferenceCache() ResourceReferenceCache {
	return &resourceReferenceCache{
		m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
	}
}

// resourceReferenceCache provides caching of resource references by ResourceKind.
type resourceReferenceCache struct {
	m  map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty
	mu sync.RWMutex
}

func (c *resourceReferenceCache) Add(kind ResourceKind, ref client.ObjectKey, referrers ...client.ObjectKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(referrers) == 0 {
		return
	}

	scope, _ := c.scoped(kind, true)
	refs, ok := scope[ref]
	if !ok {
		refs = map[client.ObjectKey]empty{}
		scope[ref] = refs
	}

	for _, r := range referrers {
		refs[r] = empty{}
	}
}

// Prune removes referrer from all references of ResourceKind.
func (c *resourceReferenceCache) Prune(kind ResourceKind, referrer client.ObjectKey) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return 0
	}

	var count int
	for k, refs := range scope {
		if _, ok := refs[referrer]; ok {
			count++
			delete(refs, referrer)
		}
		if len(refs) == 0 {
			delete(scope, k)
		}
	}

	if len(scope) == 0 {
		delete(c.m, kind)
	}

	return count
}

// Get all references to ref for ResourceKind. Returns true in ref is in the cache.
func (c *resourceReferenceCache) Get(kind ResourceKind, ref client.ObjectKey) ([]client.ObjectKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return nil, false
	}

	r, ok := scope[ref]
	if !ok {
		return nil, false
	}

	// object keys that refer to reference
	var refs []client.ObjectKey
	for ref := range r {
		refs = append(refs, ref)
	}

	return refs, true
}

// Remove ref and all of its referrers for ResourceKind.
func (c *resourceReferenceCache) Remove(kind ResourceKind, ref client.ObjectKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return false
	}

	_, ok = scope[ref]
	delete(scope, ref)

	// remove kind if the cache no longer has references of that kind
	if len(scope) == 0 {
		delete(c.m, kind)
	}

	return ok
}

func (c *resourceReferenceCache) scoped(kind ResourceKind, init bool) (map[client.ObjectKey]map[client.ObjectKey]empty, bool) {
	scope, ok := c.m[kind]
	if init && !ok {
		scope = map[client.ObjectKey]map[client.ObjectKey]empty{}
		c.m[kind] = scope
	}
	return scope, ok
}

func NewSyncRegistry() *SyncRegistry {
	return &SyncRegistry{
		m: map[client.ObjectKey]empty{},
	}
}

type SyncRegistry struct {
	m  map[client.ObjectKey]empty
	mu sync.RWMutex
}

func (r *SyncRegistry) Add(objKey client.ObjectKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.m[objKey] = empty{}
}

func (r *SyncRegistry) Remove(objKey client.ObjectKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.m, objKey)
}

func (r *SyncRegistry) Contains(objKey client.ObjectKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.m[objKey]

	return ok
}
