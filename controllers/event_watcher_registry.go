// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"

	gocache "github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/types"
)

// eventWatcherMeta - metadata for controlling an event watcher goroutine
type eventWatcherMeta struct {
	// Cancel will close the watcher's context (and stop the watcher goroutine)
	Cancel context.CancelFunc
	// Namespace in Vault for the secret that's being watched
	Namespace string
	// Type of the KV secret that's being watched
	Type string
	// Path in Vault for the secret that's being watched
	Path string
}

type EventWatcherRegistry struct {
	registry *gocache.Cache
}

func newEventWatcherRegistry() *EventWatcherRegistry {
	return &EventWatcherRegistry{
		registry: gocache.New(gocache.NoExpiration, gocache.NoExpiration),
	}
}

func (r *EventWatcherRegistry) Register(key types.NamespacedName, meta *eventWatcherMeta) {
	r.registry.Set(key.String(), meta, gocache.NoExpiration)
}

func (r *EventWatcherRegistry) Get(key types.NamespacedName) (*eventWatcherMeta, bool) {
	meta, ok := r.registry.Get(key.String())
	if !ok {
		return nil, false
	}

	return meta.(*eventWatcherMeta), true
}

func (r *EventWatcherRegistry) Delete(key types.NamespacedName) {
	r.registry.Delete(key.String())
}
