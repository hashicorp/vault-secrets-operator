// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ResourceKind int

const (
	SecretTransformation ResourceKind = iota
	VaultDynamicSecret
	VaultStaticSecret
	VaultPKISecret
	HCPVaultSecretsApp
)

func (k ResourceKind) String() string {
	switch k {
	case SecretTransformation:
		return "SecretTransformation"
	case VaultDynamicSecret:
		return "VaultDynamicSecret"
	case VaultStaticSecret:
		return "VaultStaticSecret"
	case VaultPKISecret:
		return "VaultPKISecret"
	case HCPVaultSecretsApp:
		return "HCPVaultSecretsApp"
	default:
		return "unknown"
	}
}

type ResourceReferenceCache interface {
	Set(ResourceKind, client.ObjectKey, ...client.ObjectKey)
	Get(ResourceKind, client.ObjectKey) []client.ObjectKey
	Remove(ResourceKind, client.ObjectKey) bool
	Prune(ResourceKind, client.ObjectKey) int
}

var _ ResourceReferenceCache = (*resourceReferenceCache)(nil)

// newResourceReferenceCache returns the default ReferenceCache that be used to
// store object references for quick access by secret controllers.
func newResourceReferenceCache() ResourceReferenceCache {
	return &resourceReferenceCache{
		m: refCacheMap{},
	}
}

// refCacheMap holds a tree of client.ObjectKey references, keyed by
// ResourceKind at the top level.
type refCacheMap map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty

// resourceReferenceCache provides access to a refCacheMap. It can be used to
// cache object references for a specific ResourceKind. It should be used
// whenever you want to cache object references for specific resource kinds.
// Typically, a CRD specifies a set of object references, with the controller
// E.g: a VaultStaticSecret refers to a set of SecretTransformation instances.
// SecretTransformation -> VaultStaticSecret -> [SecretTransformation, ...]
// populating the cache with all references to a specific resource kind. Then a
// Watch is set for that kind on the secret controller with a
// ResourceReferenceCache aware handler.EventHandler. That handler enqueues all
// objects that refer to the object for the handled event e.g: event.UpdateEvent.
type resourceReferenceCache struct {
	m  refCacheMap
	mu sync.RWMutex
}

// Set references of kind for referrer.
func (c *resourceReferenceCache) Set(kind ResourceKind, referrer client.ObjectKey, references ...client.ObjectKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope, _ := c.scoped(kind, true)
	if len(references) == 0 {
		delete(scope, referrer)
		if len(scope) == 0 {
			delete(c.m, kind)
		}
		return
	}

	refs := map[client.ObjectKey]empty{}
	for _, r := range references {
		refs[r] = empty{}
	}

	scope[referrer] = refs
}

// Prune reference of kind from the cache.
func (c *resourceReferenceCache) Prune(kind ResourceKind, reference client.ObjectKey) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return 0
	}

	var count int
	for referrer, references := range scope {
		if _, ok := references[reference]; ok {
			count++
			delete(references, reference)
		}
		if len(references) == 0 {
			delete(scope, referrer)
		}
	}

	if len(scope) == 0 {
		delete(c.m, kind)
	}

	return count
}

// Get all client.ObjectKey that refer to reference of kind.
func (c *resourceReferenceCache) Get(kind ResourceKind, reference client.ObjectKey) []client.ObjectKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return nil
	}

	var refs []client.ObjectKey
	for ref, v := range scope {
		if _, ok := v[reference]; ok {
			refs = append(refs, ref)
		}
	}

	return refs
}

// Remove all references of kind for referrer.
func (c *resourceReferenceCache) Remove(kind ResourceKind, referrer client.ObjectKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	scope, ok := c.scoped(kind, false)
	if !ok {
		return false
	}

	_, ok = scope[referrer]
	delete(scope, referrer)

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

// NewSyncRegistry returns a SyncRegistry.
func NewSyncRegistry() *SyncRegistry {
	return &SyncRegistry{
		m: map[client.ObjectKey]empty{},
	}
}

// SyncRegistry returns a SyncRegistry that stores sync requests for a
// client.Object. When an object is found in the registry it must be synced by
// the corresponding secret controller. Typically, the SyncRegistry is only
// needed by controllers that support renewing a Vault secret lease during
// reconciliation, or have some sync window detection.
type SyncRegistry struct {
	m  map[client.ObjectKey]empty
	mu sync.RWMutex
}

// Add objKey to the set of registered objects.
func (r *SyncRegistry) Add(objKey client.ObjectKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.m[objKey] = empty{}
}

// Delete objKey to the set of registered objects.
func (r *SyncRegistry) Delete(objKey client.ObjectKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.m, objKey)
}

// Has returns true if objKey is in the set of registered objects.
func (r *SyncRegistry) Has(objKey client.ObjectKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.m[objKey]

	return ok
}

func (r *SyncRegistry) ObjectKeys() []client.ObjectKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []client.ObjectKey
	for k := range r.m {
		result = append(result, k)
	}

	return result
}
