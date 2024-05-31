// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// Test the event watcher registry basics
func TestEventWatcherRegistry(t *testing.T) {
	// Create a new registry
	registry := newEventWatcherRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{})

	// Create a new event watcher metadata
	meta := &eventWatcherMeta{
		LastGeneration: 123,
		LastClientID:   "client-id",
		Cancel:         cancel,
		StoppedCh:      stoppedCh,
	}

	// Register the event watcher
	itemName := types.NamespacedName{Name: "test", Namespace: "default"}
	registry.Register(itemName, meta)

	// close the channel
	close(stoppedCh)

	// Get the event watcher
	got, ok := registry.Get(itemName)
	require.True(t, ok, "expected to get event watcher, got none")
	require.NotNil(t, got, "expected to get event watcher, got nil")

	assert.Equal(t, int64(123), got.LastGeneration)
	assert.Equal(t, "client-id", got.LastClientID)

	// Cancel context received from the registry, check the original
	got.Cancel()
	assert.Equal(t, ctx.Err(), context.Canceled)

	_, isOpen := <-got.StoppedCh
	assert.False(t, isOpen, "expected stoppedCh from registry item to be closed")

	// Delete the event watcher
	registry.Delete(itemName)

	// Get the event watcher
	got, ok = registry.Get(itemName)
	assert.False(t, ok, "expected to not get event watcher, got one")
	assert.Nil(t, got, "expected nil event watcher")
}
