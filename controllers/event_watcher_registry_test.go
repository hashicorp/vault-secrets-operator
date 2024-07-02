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
	assert.Equal(t, 0, registry.registry.ItemCount())

	ctx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)

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
	assert.Equal(t, 1, registry.registry.ItemCount())

	// close the channel
	close(stoppedCh)

	// Get the event watcher
	got, ok := registry.Get(itemName)
	require.True(t, ok, "expected to get event watcher, got none")
	require.NotNil(t, got, "expected to get event watcher, got nil")

	assert.Equal(t, int64(123), got.LastGeneration)
	assert.Equal(t, "client-id", got.LastClientID)

	// Update something
	got.LastGeneration = 456
	registry.Register(itemName, got)
	assert.Equal(t, 1, registry.registry.ItemCount())

	// Get again
	gotAgain, ok := registry.Get(itemName)
	require.True(t, ok, "expected to get event watcher again, got none")
	require.NotNil(t, gotAgain, "expected to get event watcher again, got nil")

	assert.Equal(t, int64(456), gotAgain.LastGeneration)
	assert.Equal(t, "client-id", gotAgain.LastClientID)

	// Cancel context received from the registry, check the original
	gotAgain.Cancel()
	assert.Equal(t, ctx.Err(), context.Canceled)

	_, isOpen := <-gotAgain.StoppedCh
	assert.False(t, isOpen, "expected stoppedCh from registry item to be closed")

	// Delete the event watcher
	registry.Delete(itemName)
	assert.Equal(t, 0, registry.registry.ItemCount())

	// Get the event watcher
	gotFinally, ok := registry.Get(itemName)
	assert.False(t, ok, "expected to not get event watcher, got one")
	assert.Nil(t, gotFinally, "expected nil event watcher")
}
