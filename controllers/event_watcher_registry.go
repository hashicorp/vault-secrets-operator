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
	// StoppedCh lets the watcher goroutine signal the caller that it has
	// stopped (and removed itself from the registry)
	StoppedCh chan struct{}
	// LastGeneration is the generation of the VaultStaticSecret resource, used
	// to detect if the event watcher needs to be recreated
	LastGeneration int64
	// LastClientID - vault client ID for the last successful connection, used
	// to detect if the Vault client has changed since the event watcher started
	LastClientID string
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
