// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

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
	RemoveObject(ctrlclient.Object) bool
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
	Prune(context.Context, ctrlclient.Client, ctrlclient.Object, CachingClientFactoryPruneRequest) (int, error)
}

var _ CachingClientFactory = (*cachingClientFactory)(nil)

type cachingClientFactory struct {
	cache       ClientCache
	objKeyCache ObjectKeyCache
	storage     ClientCacheStorage
	recorder    record.EventRecorder
	persist     bool
	logger      logr.Logger
	mu          sync.RWMutex
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
			other, err := c.GetVaultAuthObj()
			if err != nil {
				return false
			}
			return req.FilterFunc(cur, other)
		}
	case *secretsv1alpha1.VaultConnection:
		filter = func(c Client) bool {
			other, err := c.GetVaultConnectionObj()
			if err != nil {
				return false
			}
			return req.FilterFunc(cur, other)
		}
	default:
		return 0, fmt.Errorf("client removal not supported for type %T", cur)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// prune the client cache for filter, pruned is a slice of cache keys
	pruned := m.cache.Prune(filter)
	var err error

	// for all cache entries pruned, remove the corresponding storage entries.
	if req.PruneStorage && m.persist && m.storage != nil {
		for _, key := range pruned {
			if _, err := m.pruneStorage(ctx, client, key); err != nil {
				err = errors.Join(err)
			}
		}
	}

	return len(pruned), err
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

func (m *cachingClientFactory) Restore(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	var err error
	var cacheKey ClientCacheKey
	if m.storage == nil {
		return nil, fmt.Errorf("restoration not possible, storage is not enabled")
	}

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		return nil, err
	}

	vc, err := m.restoreClient(ctx, client, obj, cacheKey)
	if err != nil {
		return nil, err
	}

	return vc, nil
}

func (m *cachingClientFactory) RemoveObject(obj ctrlclient.Object) bool {
	return m.objKeyCache.Remove(ctrlclient.ObjectKeyFromObject(obj))
}

// GetClient is meant to be called for all resources that require access to Vault.
// It will attempt to fetch a Client from the in-memory cache for the provided Object.
// On a cache miss, an attempt at restoration from storage will be made, if a restoration attempt fails,
// a new Client will be instantiated, and an attempt to login into Vault will be made.
// Upon successful restoration/instantiation/login, the Client will be cached for calls.
func (m *cachingClientFactory) GetClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	logger := log.FromContext(ctx).WithName("CachingClientFactory")
	logger.Info("Cache info", "length", m.cache.Len())
	objKey := ctrlclient.ObjectKeyFromObject(obj)
	////cacheKey, inObjKeyCache := m.objKeyCache.Get(objKey)
	//if !inObjKeyCache {
	ck, err := ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		return nil, err
	}
	cacheKey := ck
	//}

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
		if restored, err := m.restoreClient(ctx, client, obj, cacheKey); err != nil {
			if !apierrors.IsNotFound(err) {
				if _, err := m.pruneStorage(ctx, client, cacheKey); err != nil {
					// remove storage entry, assuming it is invalid
				}
			}
		} else {
			c = restored
		}
	}

	if c != nil {
		// got the Client from the cache, now let's check that is not expired
		if expired, err := c.CheckExpiry(0); !expired && err == nil {
			// good to go, now cache it
			cacheKey, err := m.cacheClient(ctx, client, c)
			if err != nil {
				return nil, err
			}

			// Cache the NamespacedName of the requesting client.Object. We use this cache to
			// reduce the number of cache key computations over time.
			m.objKeyCache.Add(objKey, cacheKey)
			// return the Client
			return c, nil
		}

		m.cache.Remove(cacheKey)
	}

	// if we couldn't produce a valid Client, create a new one, log it in, and cache it
	c, err = NewClientWithLogin(ctx, client, obj)
	if err != nil {
		return nil, err
	}

	// cache the new Client for future requests.
	cacheKey, err = m.cacheClient(ctx, client, c)
	if err != nil {
		return nil, err
	}

	// again store the NamespaceName for future GetClient() requests.
	m.objKeyCache.Add(objKey, cacheKey)

	if m.persist && m.storage != nil {
		_, err := m.storage.Store(ctx, client, ClientCacheStorageRequest{
			OwnerReferences: nil,
			// TODO: wire up Transit encryption
			// TransitObjKey:        ctrlclient.ObjectKey{},
			Client:            c,
			EnforceEncryption: false,
		})
		if err != nil {
			// this should not be fatal, so we can rely on the event recorder to provide the necessary warning
			m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonPersistenceFailed,
				"Failed to store the Client to the cache, err=%s", err)
		}
	}

	return c, nil
}

func (m *cachingClientFactory) storeClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, c Client) error {
	if !m.persist || m.storage == nil {
		return fmt.Errorf("storing impossible, storage is not enabled")
	}

	// TODO: move transit config to VaultAuth
	req := ClientCacheStorageRequest{
		// TransitObjKey:     transitObjKey,
		// EnforceEncryption: enforceEncryption,
		Client: c,
	}

	if _, err := m.storage.Store(ctx, client, req); err != nil {
		return err
	}

	return nil
}

func (m *cachingClientFactory) restoreClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, cacheKey ClientCacheKey) (Client, error) {
	if !m.persist || m.storage == nil {
		return nil, fmt.Errorf("restoration impossible, storage is not enabled")
	}

	req := ClientCacheStorageRestoreRequest{
		SecretObjKey: types.NamespacedName{
			Namespace: common.OperatorNamespace,
			Name:      fmt.Sprintf("%s%s", NamePrefixVCC, cacheKey),
		},
		CacheKey: cacheKey,
	}

	apiSecret, err := m.storage.Restore(ctx, client, req)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonCacheRestorationFailed,
			"Cache restoration failed, err=%s", err)
		return nil, err
	}

	c, err := NewClient(ctx, client, obj)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client instantiation failed, err=%s", err)
		return nil, err
	}

	if err := c.Restore(ctx, apiSecret); err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client could not be restored, err=%s", err)
		return nil, err
	}

	restoredCacheKey, err := m.cacheClient(ctx, client, c)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client could not be cached, err=%s", err)
		return nil, err
	}

	if restoredCacheKey != req.CacheKey {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Restored Vault Client's cacheKey differs from the request's, requested=%s, actual=%s ",
			restoredCacheKey, req.CacheKey)
		return nil, err
	}

	m.recorder.Eventf(obj, v1.EventTypeNormal, consts.ReasonCacheRestorationSucceeded,
		"Successfully restored Vault Client from storage cache, cacheKey=%s", cacheKey)
	return c, nil
}

// cacheClient to the global in-memory cache.
func (m *cachingClientFactory) cacheClient(ctx context.Context, client ctrlclient.Client, c Client) (ClientCacheKey, error) {
	logger := log.FromContext(ctx).WithName("CachingClientFactory")
	var errs error
	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return "", err
	}

	if _, err := m.cache.Add(c); err != nil {
		logger.Error(err, "Failed to added to the cache", "client", c)
		return "", errs
	}
	logger.V(consts.LogLevelDebug).Info("Cached the client", "cacheKey", cacheKey)

	return cacheKey, nil
}

// NewCachingClientFactory returns a CachingClientFactory with ClientCache initialized.
// The ClientCache's onEvictCallback is registered with the factory's onClientEvict(),
// to ensure any evictions are handled by the factory (this is very important).
func NewCachingClientFactory(ctx context.Context,
	client ctrlclient.Client, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig,
) (CachingClientFactory, error) {
	objKeyCache, err := NewObjectKeyCache(config.ObjectKeyCacheSize)
	if err != nil {
		err = errors.Join(err)
	}

	factory := &cachingClientFactory{
		objKeyCache: objKeyCache,
		storage:     cacheStorage,
		recorder:    config.Recorder,
		persist:     config.Persist,
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

	factory.cache = cache

	return factory, nil
}

// CachingClientFactoryConfig provides the configuration for a CachingClientFactory instance.
type CachingClientFactoryConfig struct {
	Persist            bool
	StorageConfig      *ClientCacheStorageConfig
	ClientCacheSize    int
	ObjectKeyCacheSize int
	Recorder           record.EventRecorder
}

// DefaultCachingClientFactoryConfig provides the default configuration for a CachingClientFactory instance.
func DefaultCachingClientFactoryConfig() *CachingClientFactoryConfig {
	return &CachingClientFactoryConfig{
		StorageConfig:      DefaultClientCacheStorageConfig(),
		ClientCacheSize:    10000,
		ObjectKeyCacheSize: 10000,
		Recorder:           &nullEventRecorder{},
	}
}

// InitCachingClientFactory initializes a CachingClientFactory along with its ClientCacheStorage.
// It is meant to be called from main.
func InitCachingClientFactory(ctx context.Context, client ctrlclient.Client, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	// TODO: add support for bulk restoration
	// TODO add support bulk pruning of the storage, in the case where we have transitioned from storage to no storage
	// TODO: pass in a valid Context and ctrlclient.Client + factory.Prune as an OnEvictFunc()
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
	} else {
	}

	clientCacheFactory, err := NewCachingClientFactory(ctx, client, clientCacheStorage, config)
	if err != nil {
		return nil, err
	}

	if config.Persist {
		// TODO: bulk restore
	}
	return clientCacheFactory, nil
}

var _ record.EventRecorder = (*nullEventRecorder)(nil)

type nullEventRecorder struct {
	record.EventRecorder
}

func (n *nullEventRecorder) Event(_ runtime.Object, _, _, _ string) {}
