// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
)

// Helper functions for event watcher registry tests

// createTestRegistry creates a new event watcher registry for testing
func createTestRegistry() *eventWatcherRegistry {
	return newEventWatcherRegistry()
}

// createTestMeta creates test event watcher metadata
func createTestMeta(generation int64, clientID string) *eventWatcherMeta {
	return &eventWatcherMeta{
		LastGeneration: generation,
		LastClientID:   clientID,
	}
}

// createTestNamespacedName creates a test NamespacedName
func createTestNamespacedName(name, namespace string) types.NamespacedName {
	return types.NamespacedName{Name: name, Namespace: namespace}
}

// registerResource registers a resource in the registry with given metadata
func registerResource(registry *eventWatcherRegistry, objKey types.NamespacedName, generation int64, clientID string) {
	meta := createTestMeta(generation, clientID)
	registry.Register(objKey, meta)
}

// registerMultipleResources registers multiple resources in the registry
func registerMultipleResources(registry *eventWatcherRegistry, resources []types.NamespacedName, generation int64, clientID string) {
	for _, res := range resources {
		registerResource(registry, res, generation, clientID)
	}
}

// verifyRegistryCount asserts the registry has expected number of items
func verifyRegistryCount(t *testing.T, registry *eventWatcherRegistry, expected int, msgAndArgs ...interface{}) {
	assert.Equal(t, expected, registry.registry.ItemCount(), msgAndArgs...)
}

// verifyResourceExists asserts a resource exists in the registry
func verifyResourceExists(t *testing.T, registry *eventWatcherRegistry, objKey types.NamespacedName) *eventWatcherMeta {
	got, ok := registry.Get(objKey)
	require.True(t, ok, "expected resource %s to exist in registry", objKey)
	require.NotNil(t, got, "expected non-nil metadata for resource %s", objKey)
	return got
}

// verifyResourceNotExists asserts a resource does not exist in the registry
func verifyResourceNotExists(t *testing.T, registry *eventWatcherRegistry, objKey types.NamespacedName) {
	got, ok := registry.Get(objKey)
	assert.False(t, ok, "expected resource %s to not exist in registry", objKey)
	assert.Nil(t, got, "expected nil metadata for resource %s", objKey)
}

// deleteMultipleResources deletes multiple resources from the registry
func deleteMultipleResources(registry *eventWatcherRegistry, resources []types.NamespacedName) {
	for _, res := range resources {
		registry.Delete(res)
	}
}

// verifyMultipleResourcesNotExist verifies multiple resources don't exist in registry
func verifyMultipleResourcesNotExist(t *testing.T, registry *eventWatcherRegistry, resources []types.NamespacedName) {
	for _, res := range resources {
		verifyResourceNotExists(t, registry, res)
	}
}

// verifyMultipleResourcesExist verifies multiple resources exist in registry
func verifyMultipleResourcesExist(t *testing.T, registry *eventWatcherRegistry, resources []types.NamespacedName) {
	for _, res := range resources {
		verifyResourceExists(t, registry, res)
	}
}

// Test the event watcher registry basics
func TestEventWatcherRegistry(t *testing.T) {
	registry := createTestRegistry()
	verifyRegistryCount(t, registry, 0)

	// Register the event subscription
	itemName := createTestNamespacedName("test", "default")
	registerResource(registry, itemName, 123, "client-id")
	verifyRegistryCount(t, registry, 1)

	// Get and verify the event subscription metadata
	got := verifyResourceExists(t, registry, itemName)
	assert.Equal(t, int64(123), got.LastGeneration)
	assert.Equal(t, "client-id", got.LastClientID)

	// Update and verify
	got.LastGeneration = 456
	registry.Register(itemName, got)
	verifyRegistryCount(t, registry, 1)

	gotAgain := verifyResourceExists(t, registry, itemName)
	assert.Equal(t, int64(456), gotAgain.LastGeneration)
	assert.Equal(t, "client-id", gotAgain.LastClientID)

	// Delete and verify cleanup
	registry.Delete(itemName)
	verifyRegistryCount(t, registry, 0)
	verifyResourceNotExists(t, registry, itemName)
}

// TestEventWatcherRegistry_CRUDContract verifies the registry's fundamental
// semantics: last-write-wins update, selective delete, idempotent delete, and
// re-register after delete. Scenarios that only exercise registry.Delete
// directly (resource deletion, reconciler error, crash recovery, orphan
// detection by client-ID change, etc.) are folded here — the registry has no
// knowledge of those production contexts and the CRUD contract is identical
// in all of them.
func TestEventWatcherRegistry_CRUDContract(t *testing.T) {
	t.Run("last-write-wins update", func(t *testing.T) {
		registry := createTestRegistry()
		key := createTestNamespacedName("vss", "default")
		registerResource(registry, key, 1, "client-1")
		registerResource(registry, key, 2, "client-2")
		registerResource(registry, key, 3, "client-3")
		got := verifyResourceExists(t, registry, key)
		assert.Equal(t, int64(3), got.LastGeneration)
		assert.Equal(t, "client-3", got.LastClientID)
	})

	t.Run("delete removes entry", func(t *testing.T) {
		registry := createTestRegistry()
		key := createTestNamespacedName("vss", "default")
		registerResource(registry, key, 1, "client-1")
		registry.Delete(key)
		verifyRegistryCount(t, registry, 0)
		verifyResourceNotExists(t, registry, key)
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		registry := createTestRegistry()
		key := createTestNamespacedName("vss", "default")
		registry.Delete(key) // never registered — must not panic
		verifyRegistryCount(t, registry, 0)
	})

	t.Run("selective delete preserves other entries", func(t *testing.T) {
		registry := createTestRegistry()
		keep := createTestNamespacedName("vss-keep", "default")
		del := createTestNamespacedName("vss-del", "default")
		registerResource(registry, keep, 1, "c")
		registerResource(registry, del, 1, "c")
		registry.Delete(del)
		verifyRegistryCount(t, registry, 1)
		verifyResourceExists(t, registry, keep)
		verifyResourceNotExists(t, registry, del)
	})

	t.Run("re-register after delete", func(t *testing.T) {
		registry := createTestRegistry()
		key := createTestNamespacedName("vss", "default")
		registerResource(registry, key, 1, "client-old")
		registry.Delete(key)
		registerResource(registry, key, 2, "client-new")
		got := verifyResourceExists(t, registry, key)
		assert.Equal(t, int64(2), got.LastGeneration)
		assert.Equal(t, "client-new", got.LastClientID)
	})

	t.Run("delete multiple entries — all removed", func(t *testing.T) {
		registry := createTestRegistry()
		resources := []types.NamespacedName{
			createTestNamespacedName("vss-1", "default"),
			createTestNamespacedName("vss-2", "default"),
			createTestNamespacedName("vss-3", "app-ns"),
		}
		registerMultipleResources(registry, resources, 1, "client-123")
		verifyRegistryCount(t, registry, 3)
		deleteMultipleResources(registry, resources)
		verifyRegistryCount(t, registry, 0)
		verifyMultipleResourcesNotExist(t, registry, resources)
	})
}

// TestEventWatcherRegistry_ConcurrentCleanup tests that concurrent Delete calls
// (e.g. multiple event loops exiting simultaneously) are handled safely.
func TestEventWatcherRegistry_ConcurrentCleanup(t *testing.T) {
	registry := newEventWatcherRegistry()

	numResources := 50
	resources := make([]types.NamespacedName, numResources)
	for i := 0; i < numResources; i++ {
		resources[i] = createTestNamespacedName(fmt.Sprintf("vss-%d", i), "default")
		registry.Register(resources[i], &eventWatcherMeta{
			LastGeneration: int64(i),
			LastClientID:   fmt.Sprintf("client-%d", i),
		})
	}
	assert.Equal(t, numResources, registry.registry.ItemCount())

	var wg sync.WaitGroup
	for _, res := range resources {
		wg.Add(1)
		go func(objKey types.NamespacedName) {
			defer wg.Done()
			registry.Delete(objKey)
		}(res)
	}
	wg.Wait()

	assert.Equal(t, 0, registry.registry.ItemCount(),
		"all entries must be gone after concurrent deletes")
}

// TestEventWatcherRegistry_CleanupOnNamespaceDeletion verifies that when a
// namespace is deleted, all registry entries for resources in that namespace
// are properly cleaned up, ensuring proper multi-tenant resource isolation.
func TestEventWatcherRegistry_CleanupOnNamespaceDeletion(t *testing.T) {
	registry := createTestRegistry()

	// Register resources in multiple namespaces
	namespacesToDelete := "app-ns"
	namespacesToKeep := "default"

	resourcesToDelete := []types.NamespacedName{
		createTestNamespacedName("vss-1", namespacesToDelete),
		createTestNamespacedName("vss-2", namespacesToDelete),
		createTestNamespacedName("vss-3", namespacesToDelete),
	}

	resourcesToKeep := []types.NamespacedName{
		createTestNamespacedName("vss-4", namespacesToKeep),
		createTestNamespacedName("vss-5", namespacesToKeep),
	}

	// Register all resources
	registerMultipleResources(registry, append(resourcesToDelete, resourcesToKeep...), 1, "client-123")
	verifyRegistryCount(t, registry, 5, "all resources should be registered")

	// Simulate namespace deletion
	deleteMultipleResources(registry, resourcesToDelete)

	// Verify only resources from deleted namespace are cleaned up
	verifyRegistryCount(t, registry, 2, "only resources from non-deleted namespace should remain")
	verifyMultipleResourcesNotExist(t, registry, resourcesToDelete)
	verifyMultipleResourcesExist(t, registry, resourcesToKeep)
}

// TestEventWatcherRegistry_NoMemoryLeak verifies that the registry doesn't leak
// memory when resources are repeatedly registered and deleted, ensuring long-term
// stability in high-churn environments.
func TestEventWatcherRegistry_NoMemoryLeak(t *testing.T) {
	registry := createTestRegistry()

	// Simulate many register/delete cycles (like in a busy cluster)
	iterations := 1000
	resourceNames := 10 // Reuse 10 resource names

	for i := 0; i < iterations; i++ {
		res := createTestNamespacedName(fmt.Sprintf("vss-%d", i%resourceNames), "default")
		registerResource(registry, res, int64(i), fmt.Sprintf("client-%d", i))
		registry.Delete(res)
	}

	// Registry should be empty after all deletions
	verifyRegistryCount(t, registry, 0, "registry should be empty after all deletions - no memory leak")

	// Verify no entries remain
	for i := 0; i < resourceNames; i++ {
		res := createTestNamespacedName(fmt.Sprintf("vss-%d", i), "default")
		verifyResourceNotExists(t, registry, res)
	}
}

// TestEventWatcherRegistry_CleanupWithHighChurn verifies registry cleanup under
// high churn (many resources being created and deleted rapidly), ensuring the
// system remains stable under heavy load.
func TestEventWatcherRegistry_CleanupWithHighChurn(t *testing.T) {
	registry := createTestRegistry()

	// Simulate high churn scenario
	numCycles := 100
	resourcesPerCycle := 10

	for cycle := 0; cycle < numCycles; cycle++ {
		// Create batch of resources
		resources := make([]types.NamespacedName, resourcesPerCycle)
		for i := 0; i < resourcesPerCycle; i++ {
			resources[i] = createTestNamespacedName(fmt.Sprintf("vss-%d", cycle*resourcesPerCycle+i), "default")
			registerResource(registry, resources[i], int64(cycle), fmt.Sprintf("client-%d", cycle))
		}

		// Verify registration
		verifyRegistryCount(t, registry, resourcesPerCycle, "all resources in cycle %d should be registered", cycle)

		// Delete all resources in this cycle
		deleteMultipleResources(registry, resources)

		// Verify cleanup after each cycle
		verifyRegistryCount(t, registry, 0, "registry should be empty after cycle %d cleanup", cycle)
	}

	// Final verification - no memory leak after high churn
	verifyRegistryCount(t, registry, 0, "registry should be empty after high churn - no memory leak")
}

// TestEventWatcherRegistry_OrphanDetectionRaceCondition verifies orphan detection
// when there's a race between cleanup and new subscription, ensuring thread-safe
// operations and consistent state management.
func TestEventWatcherRegistry_OrphanDetectionRaceCondition(t *testing.T) {
	registry := createTestRegistry()

	objKey := createTestNamespacedName("vss-race", "default")

	// Simulate race condition scenario
	var wg sync.WaitGroup

	// Goroutine 1: Detects orphan and tries to clean up
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond) // Small delay
		// Orphan detection finds dead WebSocket
		registry.Delete(objKey)
	}()

	// Goroutine 2: New subscription tries to register
	wg.Add(1)
	go func() {
		defer wg.Done()
		meta := &eventWatcherMeta{
			LastGeneration: 2,
			LastClientID:   "client-new",
		}
		registry.Register(objKey, meta)
	}()

	wg.Wait()

	// After race, registry should be in consistent state
	// Either entry exists (new subscription won) or doesn't (cleanup won)
	count := registry.registry.ItemCount()
	assert.True(t, count == 0 || count == 1, "registry should be in consistent state after race")

	if count == 1 {
		// If entry exists, it should be the new one
		got, ok := registry.Get(objKey)
		assert.True(t, ok)
		// Could be either generation depending on race outcome
		assert.NotNil(t, got)
	}
}

// TestEventWatcherRegistry_OrphanDetectionClientIDChange verifies orphan detection
// when Vault client ID changes (new auth, token rotation, etc.), ensuring proper
// cleanup during authentication lifecycle changes.
func TestEventWatcherRegistry_OrphanDetectionClientIDChange(t *testing.T) {
	registry := createTestRegistry()

	objKey := createTestNamespacedName("vss-client-change", "default")

	// Register with original client
	registerResource(registry, objKey, 1, "client-original")

	// Verify registration
	got := verifyResourceExists(t, registry, objKey)
	assert.Equal(t, "client-original", got.LastClientID)

	// Detect orphan (client ID mismatch)
	currentClientID := "client-new"
	if got.LastClientID != currentClientID {
		registry.Delete(objKey)
	}

	// Verify orphaned entry is cleaned up
	verifyRegistryCount(t, registry, 0)
	verifyResourceNotExists(t, registry, objKey)

	// Register with new client
	registerResource(registry, objKey, 1, currentClientID)

	// Verify new entry exists
	got = verifyResourceExists(t, registry, objKey)
	assert.Equal(t, currentClientID, got.LastClientID)
}
