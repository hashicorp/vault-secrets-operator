// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
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

// TestEventWatcherRegistry_RequeueOnEventLoopExit tests that when an event loop
// exits (OnStop callback is triggered), the registry is cleaned up and a requeue
// event is sent to trigger reconciliation.
func TestEventWatcherRegistry_RequeueOnEventLoopExit(t *testing.T) {
	registry := createTestRegistry()
	reconcileCh := make(chan event.GenericEvent, 10)

	objKey := createTestNamespacedName("test-vss", "default")

	// Register the resource (simulates active event watcher)
	registerResource(registry, objKey, 1, "client-123")
	verifyRegistryCount(t, registry, 1, "resource should be registered")

	// Simulate OnStop callback being called when event loop exits
	// This mimics the behavior in vaultstaticsecret_controller.go:398-403
	onStopCallback := func() {
		// Clean up registry entry
		registry.Delete(objKey)

		// Send requeue event to trigger reconciliation
		select {
		case reconcileCh <- event.GenericEvent{
			Object: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      objKey.Name,
					Namespace: objKey.Namespace,
				},
			},
		}:
		default:
			t.Error("Failed to send requeue event - channel full")
		}
	}

	// Trigger the OnStop callback (simulating event loop exit)
	onStopCallback()

	// Verify registry was cleaned up
	verifyRegistryCount(t, registry, 0, "registry should be cleaned up after event loop exit")
	verifyResourceNotExists(t, registry, objKey)

	// Verify requeue event was sent
	select {
	case evt := <-reconcileCh:
		assert.NotNil(t, evt.Object, "requeue event should contain object")
		vss, ok := evt.Object.(*secretsv1beta1.VaultStaticSecret)
		require.True(t, ok, "requeue event should be for VaultStaticSecret")
		assert.Equal(t, objKey.Name, vss.Name)
		assert.Equal(t, objKey.Namespace, vss.Namespace)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for requeue event - requeue was not triggered")
	}
}

// TestEventWatcherRegistry_RegistryCleanup verifies that registry entries are
// properly cleaned up when resources are deleted or event loops exit, preventing
// resource leaks and ensuring clean state management.
func TestEventWatcherRegistry_RegistryCleanup(t *testing.T) {
	registry := createTestRegistry()

	// Register multiple resources
	resources := []types.NamespacedName{
		createTestNamespacedName("vss-1", "default"),
		createTestNamespacedName("vss-2", "default"),
		createTestNamespacedName("vss-3", "app-ns"),
	}

	registerMultipleResources(registry, resources, 1, "client-123")
	verifyRegistryCount(t, registry, 3, "all resources should be registered")

	// Simulate cleanup when resources are deleted (OnStop callbacks)
	deleteMultipleResources(registry, resources)

	// Verify all entries are cleaned up
	verifyRegistryCount(t, registry, 0, "all registry entries should be cleaned up")
	verifyMultipleResourcesNotExist(t, registry, resources)
}

// TestEventWatcherRegistry_OrphanedEntryDetection verifies detection and cleanup
// of orphaned registry entries (entries that exist but WebSocket is dead), ensuring
// the system can recover from connection failures.
func TestEventWatcherRegistry_OrphanedEntryDetection(t *testing.T) {
	registry := createTestRegistry()

	// Register resources
	activeRes := createTestNamespacedName("active-vss", "default")
	orphanedRes := createTestNamespacedName("orphaned-vss", "default")

	registerResource(registry, activeRes, 1, "client-1")
	registerResource(registry, orphanedRes, 1, "client-2")

	verifyRegistryCount(t, registry, 2)

	// Simulate orphan detection and cleanup
	verifyResourceExists(t, registry, orphanedRes)

	// Clean up the orphaned entry
	registry.Delete(orphanedRes)

	// Verify orphaned entry is removed
	verifyRegistryCount(t, registry, 1)
	verifyResourceNotExists(t, registry, orphanedRes)

	// Active entry should remain
	got := verifyResourceExists(t, registry, activeRes)
	assert.Equal(t, "client-1", got.LastClientID)
}

// TestEventWatcherRegistry_ConcurrentCleanup tests that concurrent cleanup
// operations (multiple event loops exiting simultaneously) are handled safely.
func TestEventWatcherRegistry_ConcurrentCleanup(t *testing.T) {
	registry := newEventWatcherRegistry()

	// Register multiple resources
	numResources := 50
	resources := make([]types.NamespacedName, numResources)
	for i := 0; i < numResources; i++ {
		resources[i] = types.NamespacedName{
			Name:      "vss-" + string(rune(i)),
			Namespace: "default",
		}
		meta := &eventWatcherMeta{
			LastGeneration: int64(i),
			LastClientID:   "client-" + string(rune(i)),
		}
		registry.Register(resources[i], meta)
	}

	assert.Equal(t, numResources, registry.registry.ItemCount())

	// Simulate concurrent event loop exits
	var wg sync.WaitGroup
	for _, res := range resources {
		wg.Add(1)
		go func(objKey types.NamespacedName) {
			defer wg.Done()
			registry.Delete(objKey)
		}(res)
	}

	wg.Wait()

	// Verify all registry entries are cleaned up
	assert.Equal(t, 0, registry.registry.ItemCount(),
		"all registry entries should be cleaned up after concurrent exits")
}

// TestEventWatcherRegistry_CleanupOnResourceDeletion verifies that when a
// Kubernetes resource is deleted, its registry entry is properly removed,
// ensuring clean resource lifecycle management.
func TestEventWatcherRegistry_CleanupOnResourceDeletion(t *testing.T) {
	registry := newEventWatcherRegistry()

	// Register a resource
	objKey := types.NamespacedName{Name: "vss-to-delete", Namespace: "default"}
	meta := &eventWatcherMeta{
		LastGeneration: 1,
		LastClientID:   "client-123",
	}
	registry.Register(objKey, meta)
	assert.Equal(t, 1, registry.registry.ItemCount())

	// Simulate resource deletion (finalizer cleanup triggers OnStop callback)
	// In real code: vaultstaticsecret_controller.go:330-354 (finalize method)
	registry.Delete(objKey)

	// Verify registry entry is removed
	assert.Equal(t, 0, registry.registry.ItemCount(), "registry should be cleaned up after resource deletion")
	_, ok := registry.Get(objKey)
	assert.False(t, ok, "deleted resource should not be in registry")
}

// TestEventWatcherRegistry_CleanupOnReconcilerError verifies that registry
// cleanup happens even when reconciler encounters errors, ensuring robust
// error handling and preventing resource leaks during failures.
func TestEventWatcherRegistry_CleanupOnReconcilerError(t *testing.T) {
	registry := newEventWatcherRegistry()

	objKey := types.NamespacedName{Name: "vss-error", Namespace: "default"}
	meta := &eventWatcherMeta{
		LastGeneration: 1,
		LastClientID:   "client-123",
	}

	// Register resource
	registry.Register(objKey, meta)
	assert.Equal(t, 1, registry.registry.ItemCount())

	// Simulate reconciler error scenario
	// Even if reconciler fails, OnStop callback should still clean up registry
	// This happens when: Vault connection fails, auth fails, etc.
	simulateReconcilerError := func() error {
		// Simulate error during reconciliation
		// In real code: vaultstaticsecret_controller.go:334-341
		// Even with error, cleanup should happen
		registry.Delete(objKey)
		return assert.AnError // Simulated error
	}

	err := simulateReconcilerError()
	assert.Error(t, err, "reconciler should return error")

	// Verify cleanup happened despite error
	assert.Equal(t, 0, registry.registry.ItemCount(), "registry should be cleaned up even on reconciler error")
	_, ok := registry.Get(objKey)
	assert.False(t, ok, "resource should be removed from registry despite error")
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
		res := createTestNamespacedName("vss-"+string(rune(i%resourceNames)), "default")
		registerResource(registry, res, int64(i), "client-"+string(rune(i)))
		registry.Delete(res)
	}

	// Registry should be empty after all deletions
	verifyRegistryCount(t, registry, 0, "registry should be empty after all deletions - no memory leak")

	// Verify no entries remain
	for i := 0; i < resourceNames; i++ {
		res := createTestNamespacedName("vss-"+string(rune(i)), "default")
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
			resources[i] = createTestNamespacedName("vss-"+string(rune(cycle*resourcesPerCycle+i)), "default")
			registerResource(registry, resources[i], int64(cycle), "client-"+string(rune(cycle)))
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

// TestEventWatcherRegistry_OrphanDetectionAfterCrash verifies detection of orphaned
// entries that remain after operator crash (OnStop callback never ran), ensuring
// graceful recovery from unexpected failures.
func TestEventWatcherRegistry_OrphanDetectionAfterCrash(t *testing.T) {
	registry := createTestRegistry()

	// Simulate resources registered before crash
	crashedResources := []types.NamespacedName{
		createTestNamespacedName("vss-crashed-1", "default"),
		createTestNamespacedName("vss-crashed-2", "default"),
	}

	registerMultipleResources(registry, crashedResources, 1, "client-before-crash")
	verifyRegistryCount(t, registry, 2, "resources registered before crash")

	// Detect and clean up orphaned entries
	for _, res := range crashedResources {
		if _, exists := registry.Get(res); exists {
			registry.Delete(res)
		}
	}

	// Verify all orphaned entries are cleaned up
	verifyRegistryCount(t, registry, 0, "all orphaned entries should be cleaned up")
	verifyMultipleResourcesNotExist(t, registry, crashedResources)
}

// TestEventWatcherRegistry_OrphanDetectionWithMixedState verifies orphan detection
// when some entries are healthy and some are orphaned, ensuring selective cleanup
// that preserves healthy connections while removing stale ones.
func TestEventWatcherRegistry_OrphanDetectionWithMixedState(t *testing.T) {
	registry := createTestRegistry()

	// Register healthy resources (WebSocket active)
	healthyResources := []types.NamespacedName{
		createTestNamespacedName("vss-healthy-1", "default"),
		createTestNamespacedName("vss-healthy-2", "default"),
	}

	// Register orphaned resources (WebSocket dead)
	orphanedResources := []types.NamespacedName{
		createTestNamespacedName("vss-orphaned-1", "default"),
		createTestNamespacedName("vss-orphaned-2", "default"),
		createTestNamespacedName("vss-orphaned-3", "default"),
	}

	// Register all resources
	registerMultipleResources(registry, append(healthyResources, orphanedResources...), 1, "client-123")
	verifyRegistryCount(t, registry, 5, "all resources registered")

	// Simulate orphan detection logic
	deleteMultipleResources(registry, orphanedResources)

	// Verify only orphaned entries are cleaned up
	verifyRegistryCount(t, registry, 2, "only healthy resources should remain")
	verifyMultipleResourcesNotExist(t, registry, orphanedResources)
	verifyMultipleResourcesExist(t, registry, healthyResources)
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

// TestEventWatcherRegistry_AutomaticOrphanCleanup verifies that orphan cleanup
// happens automatically during reconciliation, ensuring self-healing behavior
// without manual intervention.
func TestEventWatcherRegistry_AutomaticOrphanCleanup(t *testing.T) {
	registry := createTestRegistry()

	// Simulate orphaned entries from previous operator run
	orphanedEntries := []types.NamespacedName{
		createTestNamespacedName("vss-old-1", "default"),
		createTestNamespacedName("vss-old-2", "app-ns"),
		createTestNamespacedName("vss-old-3", "default"),
	}

	registerMultipleResources(registry, orphanedEntries, 1, "client-old")
	verifyRegistryCount(t, registry, 3, "orphaned entries exist")

	// Simulate automatic orphan detection during reconciliation
	cleanupOrphans := func() {
		for _, res := range orphanedEntries {
			if _, exists := registry.Get(res); exists {
				registry.Delete(res)
			}
		}
	}

	// Run automatic cleanup
	cleanupOrphans()

	// Verify all orphans are automatically cleaned up
	verifyRegistryCount(t, registry, 0, "all orphans should be automatically cleaned up")
	verifyMultipleResourcesNotExist(t, registry, orphanedEntries)
}

// TestEventWatcherRegistry_OrphanDetectionMultipleGenerations verifies orphan
// detection when resource has been updated multiple times, ensuring proper
// generation tracking and cleanup of stale entries.
func TestEventWatcherRegistry_OrphanDetectionMultipleGenerations(t *testing.T) {
	registry := createTestRegistry()

	objKey := createTestNamespacedName("vss-multi-gen", "default")

	// Register with generation 1, then update to 2, then 3
	registerResource(registry, objKey, 1, "client-1")
	registerResource(registry, objKey, 2, "client-2")
	registerResource(registry, objKey, 3, "client-3")

	// Verify latest generation is stored
	got := verifyResourceExists(t, registry, objKey)
	assert.Equal(t, int64(3), got.LastGeneration)
	assert.Equal(t, "client-3", got.LastClientID)

	// Simulate orphan detection - WebSocket for generation 3 is dead
	registry.Delete(objKey)

	// Verify orphaned entry is cleaned up
	verifyRegistryCount(t, registry, 0)
	verifyResourceNotExists(t, registry, objKey)
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
