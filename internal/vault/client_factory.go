// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/log"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

const (
	NamePrefixVCC = "vso-cc-"
)

type ClientFactory interface {
	GetClient(context.Context, ctrlclient.Client, ctrlclient.Object) (Client, error)
}

// clientCacheObjectFilterFunc provides a way to selectively prune  CachingClientFactory's Client cache.
type clientCacheObjectFilterFunc func(cur, other ctrlclient.Object) bool

type CachingClientFactoryPruneRequest struct {
	FilterFunc   clientCacheObjectFilterFunc
	PruneStorage bool
}

type CachingClientFactory interface {
	ClientFactory
	Restore(context.Context, ctrlclient.Client, ctrlclient.Object) (Client, error)
	RestoreAll(context.Context, ctrlclient.Client) error
	Prune(context.Context, ctrlclient.Client, ctrlclient.Object, CachingClientFactoryPruneRequest) (int, error)
}

var _ CachingClientFactory = (*cachingClientFactory)(nil)

type cachingClientFactory struct {
	cache              ClientCache
	storage            ClientCacheStorage
	recorder           record.EventRecorder
	persist            bool
	encryptionRequired bool
	// clientCacheKeyEncrypt is a member of the ClientCache, it is instantiated whenever the ClientCacheStorage has enforceEncryption enabled.
	clientCacheKeyEncrypt ClientCacheKey
	logger                logr.Logger
	mu                    sync.RWMutex
}

// Prune the storage for the requesting object and CachingClientFactoryPruneRequest.
// Supported, requesting client.Object(s), are: v1alpha1.VaultAuth, v1alpha1.VaultConnection.
// Then number of pruned storage Secrets will be returned, along with any errors encountered.
// Pruning continues on error, so there is a possibility that only a subset of the requested Secrets will be removed
// from the ClientCacheStorage.
func (m *cachingClientFactory) Prune(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, req CachingClientFactoryPruneRequest) (int, error) {
	var filter ClientCachePruneFilterFunc
	switch cur := obj.(type) {
	case *secretsv1alpha1.VaultAuth:
		filter = func(c Client) bool {
			other := c.GetVaultAuthObj()
			return req.FilterFunc(cur, other)
		}
	case *secretsv1alpha1.VaultConnection:
		filter = func(c Client) bool {
			other := c.GetVaultConnectionObj()
			return req.FilterFunc(cur, other)
		}
	default:
		return 0, fmt.Errorf("client removal not supported for type %T", cur)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// prune the client cache for filter, pruned is a slice of cache keys
	pruned := m.cache.Prune(filter)
	var errs error
	// for all cache entries pruned, remove the corresponding storage entries.
	if req.PruneStorage && m.persist && m.storage != nil {
		for _, key := range pruned {
			if _, err := m.pruneStorage(ctx, client, key); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}

	return len(pruned), errs
}

// pruneStorage of all stored Secrets matching the cacheKey.
func (m *cachingClientFactory) pruneStorage(ctx context.Context, client ctrlclient.Client, cacheKey ClientCacheKey) (int, error) {
	return m.storage.Prune(ctx, client, ClientCacheStoragePruneRequest{
		MatchingLabels: map[string]string{
			labelCacheKey: cacheKey.String(),
		},
		Filter: func(_ v1.Secret) bool {
			return false
		},
	})
}

// onClientEvict should be called whenever an eviction from the ClientCache occurs.
// It should always call Client.Close() to prevent leaking Go routines.
func (m *cachingClientFactory) onClientEvict(ctx context.Context, client ctrlclient.Client, cacheKey ClientCacheKey, c Client) {
	logger := m.logger.WithValues("cacheKey", cacheKey)
	logger.Info("Handling client cache eviction")
	c.Close()
	if m.persist && m.storage != nil {
		if count, err := m.pruneStorage(ctx, client, cacheKey); err != nil {
			logger.Error(err, "Failed to remove Client from storage")
		} else {
			logger.Info("Pruned storage", "count", count)
		}
	}
}

// Restore will attempt to restore a Client from storage. If storage is not enabled then no restoration will take place.
// a nil Client will be returned in this case. so that should be handled by all callers.
func (m *cachingClientFactory) Restore(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	var err error
	var cacheKey ClientCacheKey
	if !m.persist || m.storage == nil {
		return nil, nil
	}

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		return nil, err
	}

	m.logger.V(consts.LogLevelDebug).Info("Restoring Client", "cacheKey", cacheKey)
	return m.restoreClientFromCacheKey(ctx, client, cacheKey)
}

// RestoreAll will attempt to restore all Client from storage. If storage is not enabled then no restoration will take place.
// Normally this should be called before the controller-manager has started reconciling any of its Custom Resources.
// Strict error checking is not necessary for the caller,
// since future calls to GetClient will ensure that the new storage entries will be created upon request
// from one of the supported Vault*Secret types. If any error is encountered, the clientCacheStorageEntry will be treated as suspect
// and pruned from the storage cache.
func (m *cachingClientFactory) RestoreAll(ctx context.Context, client ctrlclient.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.persist || m.storage == nil {
		return nil
	}

	req, err := m.restoreAllRequest(ctx, client)
	if err != nil {
		return err
	}

	entries, err := m.storage.RestoreAll(ctx, client, req)
	if err != nil {
		m.logger.Error(err, "RestoreAll failed from storage")
		return err
	}
	if entries == nil {
		return nil
	}

	var errs error
	pruneIt := func(entry *clientCacheStorageEntry) {
		if _, err := m.pruneStorage(ctx, client, entry.CacheKey); err != nil {
			m.logger.Error(err, "Failed to prune invalid storage entry", "cacheKey", entry.CacheKey)
			errs = errors.Join(errs, err)
		}
	}
	// this is a bit challenging, since we really only want to restore Clients that are actually needed by any of the Vault*Secret types.
	m.logger.Info("Restoring all Clients from storage", "numEntries", len(entries))
	for _, entry := range entries {
		m.logger.Info("Restoring", "cacheKey", entry.CacheKey)
		_, err := m.restoreClient(ctx, client, entry)
		if err != nil {
			m.logger.Error(err, "Restore failed", "cacheKey", entry.CacheKey)
			errs = errors.Join(errs, err)
			pruneIt(entry)
			continue
		}

		m.logger.Info("Successfully restored the Client", "cacheKey", entry.CacheKey)
	}
	return errs
}

// GetClient is meant to be called for all resources that require access to Vault.
// It will attempt to fetch a Client from the in-memory cache for the provided Object.
// On a cache miss, an attempt at restoration from storage will be made, if a restoration attempt fails,
// a new Client will be instantiated, and an attempt to login into Vault will be made.
// Upon successful restoration/instantiation/login, the Client will be cached for calls.
func (m *cachingClientFactory) GetClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	logger := log.FromContext(ctx).WithName("cachingClientFactory")
	logger.V(consts.LogLevelDebug).Info("Cache info", "length", m.cache.Len())
	cacheKey, err := ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		logger.Error(err, "Failed to get cacheKey from obj")
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		return nil, err
	}

	// try and fetch the client from the in-memory Client cache
	c, ok := m.cache.Get(cacheKey)
	if ok {
		// return the Client from the cache if it is not expired.
		if expired, err := c.CheckExpiry(0); !expired && err == nil {
			return c, nil
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !ok && (m.persist && m.storage != nil) {
		// try and restore from Client storage cache, if properly configured to do so.
		if restored, err := m.restoreClientFromCacheKey(ctx, client, cacheKey); err == nil {
			return restored, nil
		}
	}

	// if we couldn't produce a valid Client, create a new one, log it in, and cache it
	c, err = NewClientWithLogin(ctx, client, obj, nil)
	if err != nil {
		logger.Error(err, "Failed to get NewClientWithLogin")
		return nil, err
	}

	// cache the new Client for future requests.
	cacheKey, err = m.cacheClient(c)
	if err != nil {
		return nil, err
	}

	if m.persist && m.storage != nil {
		if err := m.storeClient(ctx, client, c); err != nil {
			logger.Error(err, "Failed to store the client")
		}
	}

	return c, nil
}

func (m *cachingClientFactory) storeClient(ctx context.Context, client ctrlclient.Client, c Client) error {
	if !m.persist || m.storage == nil {
		return fmt.Errorf("storing impossible, storage is not enabled")
	}

	// TODO: move transit config to VaultAuth
	req := ClientCacheStorageStoreRequest{
		Client: c,
	}

	if m.encryptionRequired {
		c, err := m.storageEncryptionClient(ctx, client)
		if err != nil {
			return err
		}
		authObj := c.GetVaultAuthObj()
		req.EncryptionClient = c
		req.EncryptionVaultAuth = authObj
	}

	if _, err := m.storage.Store(ctx, client, req); err != nil {
		return err
	}

	return nil
}

func (m *cachingClientFactory) getClientCacheStorageEntry(ctx context.Context, client ctrlclient.Client, cacheKey ClientCacheKey) (*clientCacheStorageEntry, error) {
	req := ClientCacheStorageRestoreRequest{
		SecretObjKey: types.NamespacedName{
			Namespace: common.OperatorNamespace,
			Name:      fmt.Sprintf("%s%s", NamePrefixVCC, cacheKey),
		},
		CacheKey: cacheKey,
	}

	if m.encryptionRequired {
		c, err := m.storageEncryptionClient(ctx, client)
		if err != nil {
			return nil, err
		}
		authObj := c.GetVaultAuthObj()
		req.DecryptionClient = c
		req.DecryptionVaultAuth = authObj
	}

	return m.storage.Restore(ctx, client, req)
}

func (m *cachingClientFactory) restoreClientFromCacheKey(ctx context.Context, client ctrlclient.Client, cacheKey ClientCacheKey) (Client, error) {
	entry, err := m.getClientCacheStorageEntry(ctx, client, cacheKey)
	if err != nil {
		return nil, err
	}

	return m.restoreClient(ctx, client, entry)
}

func (m *cachingClientFactory) restoreClient(ctx context.Context, client ctrlclient.Client, entry *clientCacheStorageEntry) (Client, error) {
	if !m.persist || m.storage == nil {
		return nil, fmt.Errorf("restoration impossible, storage is not enabled")
	}

	c, err := NewClientFromStorageEntry(ctx, client, entry, nil)
	if err != nil {
		return nil, err
	}

	if _, err := m.cacheClient(c); err != nil {
		return nil, err
	}

	return c, nil
}

// cacheClient to the global in-memory cache.
func (m *cachingClientFactory) cacheClient(c Client) (ClientCacheKey, error) {
	var errs error
	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return "", err
	}

	if _, err := m.cache.Add(c); err != nil {
		m.logger.Error(err, "Failed to added to the cache", "client", c)
		return "", errs
	}
	m.logger.V(consts.LogLevelDebug).Info("Cached the client", "cacheKey", cacheKey)

	return cacheKey, nil
}

// storageEncryptionClient sets up a Client from a VaultAuth object that supports Transit encryption.
// The result is cached in the ClientCache for future needs. This should only ever be need if the ClientCacheStorage
// has enforceEncryption enabled.
func (m *cachingClientFactory) storageEncryptionClient(ctx context.Context, client ctrlclient.Client) (Client, error) {
	if m.clientCacheKeyEncrypt == "" {
		encryptionVaultAuth, err := common.FindVaultAuthForStorageEncryption(ctx, client)
		if err != nil {
			return nil, err
		}

		// if we couldn't produce a valid Client, create a new one, log it in, and cache it
		vc, err := NewClientWithLogin(ctx, client, encryptionVaultAuth, nil)
		if err != nil {
			return nil, err
		}

		// cache the new Client for future requests.
		cacheKey, err := m.cacheClient(vc)
		if err != nil {
			return nil, err
		}

		m.clientCacheKeyEncrypt = cacheKey
	}

	c, ok := m.cache.Get(m.clientCacheKeyEncrypt)
	if !ok {
		return nil, fmt.Errorf("expected Client for storage encryption not found in the cache, "+
			"cacheKey=%s", m.clientCacheKeyEncrypt)
	}

	return c, nil
}

func (m *cachingClientFactory) restoreAllRequest(ctx context.Context, client ctrlclient.Client) (ClientCacheStorageRestoreAllRequest, error) {
	req := ClientCacheStorageRestoreAllRequest{}
	if m.encryptionRequired {
		c, err := m.storageEncryptionClient(ctx, client)
		if err != nil {
			return req, err
		}
		req.DecryptionVaultAuth = c.GetVaultAuthObj()
		req.DecryptionClient = c
	}

	return req, nil
}

// NewCachingClientFactory returns a CachingClientFactory with ClientCache initialized.
// The ClientCache's onEvictCallback is registered with the factory's onClientEvict(),
// to ensure any evictions are handled by the factory (this is very important).
func NewCachingClientFactory(ctx context.Context, client ctrlclient.Client, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	factory := &cachingClientFactory{
		storage:            cacheStorage,
		recorder:           config.Recorder,
		persist:            config.Persist,
		encryptionRequired: config.StorageConfig.EnforceEncryption,
		logger: zap.New().WithName("clientCacheFactory").WithValues(
			"persist", config.Persist,
			"enforceEncryption", config.StorageConfig.EnforceEncryption,
		),
	}

	// adds an onEvictCallbackFunc to the ClientCache
	// the function must always call Client.Close() to avoid leaking Go routines
	cache, err := NewClientCache(config.ClientCacheSize, func(key, value interface{}) {
		factory.onClientEvict(ctx, client, key.(ClientCacheKey), value.(Client))
	})
	if err != nil {
		return nil, err
	}

	factory.cache = cache
	return factory, nil
}

// CachingClientFactoryConfig provides the configuration for a CachingClientFactory instance.
type CachingClientFactoryConfig struct {
	Persist         bool
	StorageConfig   *ClientCacheStorageConfig
	ClientCacheSize int
	Recorder        record.EventRecorder
}

// DefaultCachingClientFactoryConfig provides the default configuration for a CachingClientFactory instance.
func DefaultCachingClientFactoryConfig() *CachingClientFactoryConfig {
	return &CachingClientFactoryConfig{
		StorageConfig:   DefaultClientCacheStorageConfig(),
		ClientCacheSize: 10000,
		Recorder:        &nullEventRecorder{},
	}
}

// InitCachingClientFactory initializes a CachingClientFactory along with its ClientCacheStorage.
// It is meant to be called from main.
func InitCachingClientFactory(ctx context.Context, client ctrlclient.Client, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	// TODO: add support for bulk restoration
	logger := zap.New().WithName("initCachingClientFactory")
	logger.Info("Initializing the CachingClientFactory")
	clientCacheStorage, err := NewDefaultClientCacheStorage(ctx, client, config.StorageConfig)
	if err != nil {
		return nil, err
	}

	if !config.Persist {
		// perform the purge to handle a transition from persistence to no persistence.
		// this ensures no leakage of cached Client Secrets.
		if err := clientCacheStorage.Purge(ctx, client); err != nil {
			return nil, err
		}
		clientCacheStorage = nil
	}

	clientCacheFactory, err := NewCachingClientFactory(ctx, client, clientCacheStorage, config)
	if err != nil {
		return nil, err
	}

	if config.Persist {
		// restore all clients from the storage cache. This should be done prior to the controller-manager starting up,
		// since we want the ClientCache fully populated before any Vault*Secret resources are reconciled.
		if err := clientCacheFactory.RestoreAll(ctx, client); err != nil {
			logger.Error(err, "RestoreAll completed with errors, please investigate")
		}
	}

	return clientCacheFactory, nil
}

var _ record.EventRecorder = (*nullEventRecorder)(nil)

type nullEventRecorder struct {
	record.EventRecorder
}

func (n *nullEventRecorder) Event(_ runtime.Object, _, _, _ string) {}
