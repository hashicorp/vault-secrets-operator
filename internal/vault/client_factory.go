// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"

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
	NamePrefixVCC = "vso-client-cache-"
)

var vccNameRe = regexp.MustCompile(fmt.Sprintf(`^%s%s$`, NamePrefixVCC, cacheKeyRe.String()))

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
	mu          sync.RWMutex
}

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
			if _, err := m.storage.Prune(ctx, client, ClientCacheStoragePruneRequest{
				MatchingLabels: map[string]string{
					"cacheKey": key,
				},
			}); err != nil {
				err = errors.Join(err)
			}
		}
	}

	return len(pruned), err
}

func (m *cachingClientFactory) Restore(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	var err error
	var cacheKey string
	if m.storage == nil {
		return nil, fmt.Errorf("restoration not possible, storage is not enabled")
	}

	cacheKey, err = GenClientCacheKeyFromObj(ctx, client, obj)
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
	ck, err := GenClientCacheKeyFromObj(ctx, client, obj)
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
		if restored, err := m.restoreClient(ctx, client, obj, cacheKey); err == nil {
			c = restored
		}
	}

	if c != nil {
		// got the Client from the cache, now let's check that is is not expired
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

		if err := c.Close(); err != nil {
			return nil, err
		}
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
			m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonPersistenceForbidden, "Failed to store the Client to the cache, err=%s", err)
		}
	}

	return c, nil
}

func (m *cachingClientFactory) storeClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, c Client) error {
	if !m.persist || m.storage == nil {
		return fmt.Errorf("restoration impossible, storage is not enabled")
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

func (m *cachingClientFactory) restoreClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, cacheKey string) (Client, error) {
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
func (m *cachingClientFactory) cacheClient(ctx context.Context, client ctrlclient.Client, c Client) (string, error) {
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
	logger.Info("Cached the client", "cacheKey", cacheKey)

	return cacheKey, nil
}

func NewCachingClientFactory(clientCache ClientCache, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	objKeyCache, err := NewObjectKeyCache(config.ObjectKeyCacheSize)
	if err != nil {
		err = errors.Join(err)
	}

	factory := &cachingClientFactory{
		cache:       clientCache,
		objKeyCache: objKeyCache,
		storage:     cacheStorage,
		recorder:    config.Recorder,
		persist:     config.Persist,
	}

	return factory, nil
}

type CachingClientFactoryConfig struct {
	Persist            bool
	StorageConfig      *ClientCacheStorageConfig
	ClientCacheSize    int
	ObjectKeyCacheSize int
	Recorder           record.EventRecorder
}

func DefaultCachingClientFactoryConfig() *CachingClientFactoryConfig {
	return &CachingClientFactoryConfig{
		StorageConfig:      DefaultClientCacheStorageConfig(),
		ClientCacheSize:    10000,
		ObjectKeyCacheSize: 10000,
		Recorder:           &nullEventRecorder{},
	}
}

func SetupCachingClientFactory(ctx context.Context, client ctrlclient.Client, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	var err error
	var clientCacheStorage ClientCacheStorage
	if config.Persist {
		clientCacheStorage, err = NewDefaultClientCacheStorage(ctx, client, config.StorageConfig)
		if err != nil {
			return nil, err
		}

	}

	cache, err := NewClientCache(config.ClientCacheSize)
	if err != nil {
		return nil, err
	}

	clientCacheFactory, err := NewCachingClientFactory(cache, clientCacheStorage, config)
	if err != nil {
		return nil, err
	}

	return clientCacheFactory, nil
}

var _ record.EventRecorder = (*nullEventRecorder)(nil)

type nullEventRecorder struct {
	record.EventRecorder
}

func (n *nullEventRecorder) Event(object runtime.Object, eventtype, reason, message string) {}
