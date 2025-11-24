// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-logr/logr"
	gocache "github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/types"
)

// eventWatcherMeta - metadata for managing an event watcher goroutine
type eventWatcherMeta struct {
	// Cancel will close the watcher's context (and stop the watcher goroutine)
	Cancel context.CancelFunc `json:"-"`
	// StoppedCh lets the watcher goroutine signal the caller that it has
	// stopped (and removed itself from the registry)
	StoppedCh chan struct{} `json:"-"`
	// LastGeneration is the generation of the VaultStaticSecret resource, used
	// to detect if the event watcher needs to be recreated
	LastGeneration int64
	// LastClientID - vault client ID for the last successful connection, used
	// to detect if the Vault client has changed since the event watcher started
	LastClientID string
	// ListenerID tracks the identifier for event listeners registered on a
	// Vault client.
	ListenerID string
	// ErrorCount records the number of consecutive errors encountered while
	// handling events for this watcher/listener.
	ErrorCount int
	// ErrorThreshold defines how many consecutive errors should trigger a
	// requeue of the resource.
	ErrorThreshold int
	// Backoff defines the retry behavior when handling errors.
	Backoff *backoff.ExponentialBackOff `json:"-"`
	// RetryCancel cancels any pending requeue timers.
	RetryCancel context.CancelFunc `json:"-"`
}

// eventWatcherRegistry - registry for keeping track of running event watcher
// goroutines keyed by object name, along with associated metadata for
// rebuilding and killing the watchers
type eventWatcherRegistry struct {
	registry *gocache.Cache
}

const defaultEventWatcherErrorThreshold = 5

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

func resetEventWatcherMeta(meta *eventWatcherMeta) {
	if meta == nil {
		return
	}
	meta.ErrorCount = 0
	if meta.Backoff != nil {
		meta.Backoff.Reset()
	}
	if meta.RetryCancel != nil {
		meta.RetryCancel()
		meta.RetryCancel = nil
	}
}

// Stop cancels the watcher/listener referenced by meta, waits for it to finish,
// and deletes the registry entry.
func (r *eventWatcherRegistry) Stop(ctx context.Context, key types.NamespacedName, meta *eventWatcherMeta, logger logr.Logger) {
	if meta == nil {
		r.Delete(key)
		return
	}

	if meta.Cancel != nil {
		meta.Cancel()
	} else if logger.GetSink() != nil {
		logger.Error(fmt.Errorf("nil cancel function"), "event watcher has nil cancel function", "key", key)
	}

	if meta.StoppedCh != nil {
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := waitForStoppedCh(waitCtx, meta.StoppedCh); err != nil && logger.GetSink() != nil {
			logger.Error(err, "Failed to stop event watcher", "key", key)
		}
	}
	if meta.RetryCancel != nil {
		meta.RetryCancel()
		meta.RetryCancel = nil
	}

	r.Delete(key)
}
