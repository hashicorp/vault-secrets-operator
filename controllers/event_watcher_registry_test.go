// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
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

	// Create a new event subscription metadata
	meta := &eventWatcherMeta{
		LastGeneration: 123,
		LastClientID:   "client-id",
	}

	// Register the event subscription
	itemName := types.NamespacedName{Name: "test", Namespace: "default"}
	registry.Register(itemName, meta)
	assert.Equal(t, 1, registry.registry.ItemCount())

	// Get the event subscription metadata
	got, ok := registry.Get(itemName)
	require.True(t, ok, "expected to get event subscription metadata, got none")
	require.NotNil(t, got, "expected to get event subscription metadata, got nil")

	assert.Equal(t, int64(123), got.LastGeneration)
	assert.Equal(t, "client-id", got.LastClientID)

	// Update something
	got.LastGeneration = 456
	registry.Register(itemName, got)
	assert.Equal(t, 1, registry.registry.ItemCount())

	// Get again
	gotAgain, ok := registry.Get(itemName)
	require.True(t, ok, "expected to get event subscription metadata again, got none")
	require.NotNil(t, gotAgain, "expected to get event subscription metadata again, got nil")

	assert.Equal(t, int64(456), gotAgain.LastGeneration)
	assert.Equal(t, "client-id", gotAgain.LastClientID)

	// Delete the event subscription
	registry.Delete(itemName)
	assert.Equal(t, 0, registry.registry.ItemCount())

	// Get the event subscription metadata
	gotFinally, ok := registry.Get(itemName)
	assert.False(t, ok, "expected to not get event subscription metadata, got one")
	assert.Nil(t, gotFinally, "expected nil event subscription metadata")
}
