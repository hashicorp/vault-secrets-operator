// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	gocache "github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/types"
)

// eventWatcherMeta - metadata for tracking event subscriptions
type eventWatcherMeta struct {
	// LastGeneration is the generation of the resource, used
	// to detect if the event subscription needs to be recreated
	LastGeneration int64
	// LastClientID - vault client ID for the last successful subscription, used
	// to detect if the Vault client has changed since the subscription started
	LastClientID string
}

// eventWatcherRegistry - registry for keeping track of running event watcher
// goroutines keyed by object name, along with associated metadata for
// rebuilding and killing the watchers
type eventWatcherRegistry struct {
	registry *gocache.Cache
}

func newEventWatcherRegistry() *eventWatcherRegistry {
	return &eventWatcherRegistry{
		registry: gocache.New(gocache.NoExpiration, gocache.NoExpiration),
	}
}

// Register - set event metadata in the registry for an object
func (r *eventWatcherRegistry) Register(key types.NamespacedName, meta *eventWatcherMeta) {
	r.registry.Set(key.String(), meta, gocache.NoExpiration)
}

// Get - retrieve event metadata from the registry for a given object
func (r *eventWatcherRegistry) Get(key types.NamespacedName) (*eventWatcherMeta, bool) {
	meta, ok := r.registry.Get(key.String())
	if !ok {
		return nil, false
	}

	return meta.(*eventWatcherMeta), true
}

// Delete - remove event metadata from the registry for a given object
func (r *eventWatcherRegistry) Delete(key types.NamespacedName) {
	r.registry.Delete(key.String())
}
