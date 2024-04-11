// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

// ClientCallbackOn is an enumeration of possible client callback events.
type ClientCallbackOn int

const (
	// ClientCallbackOnLifetimeWatcherDone is a ClientCallbackOn that handles client
	// lifetime watcher done events.
	ClientCallbackOnLifetimeWatcherDone ClientCallbackOn = iota
	NamePrefixVCC                                        = "vso-cc-"
)

// ClientCallback is a function type that takes a context, a Client, and an error as parameters.
// It is used in the context of a ClientCallbackHandler.
type ClientCallback func(ctx context.Context, c Client, err error)

// ClientCallbackHandler is a struct that contains a ClientCallbackOn enumeration
// and a ClientCallback function. It is used to register event handlers for
// specific events in the lifecycle of a Client.
type ClientCallbackHandler struct {
	On       ClientCallbackOn
	Callback ClientCallback
}

type ClientFactoryDisabledError struct{}

func (e *ClientFactoryDisabledError) Error() string {
	return "ClientFactory disabled due to operator deployment deletion"
}

type ClientFactory interface {
	Get(context.Context, ctrlclient.Client, ctrlclient.Object) (Client, error)
	RegisterClientCallbackHandler(ClientCallbackHandler)
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
	Start(context.Context)
	Stop()
	ShutDown(CachingClientFactoryShutDownRequest)
}

var _ CachingClientFactory = (*cachingClientFactory)(nil)

type cachingClientFactory struct {
	cache              ClientCache
	storage            ClientCacheStorage
	recorder           record.EventRecorder
	persist            bool
	encryptionRequired bool
	shutDown           bool
	// clientCacheKeyEncrypt is a member of the ClientCache, it is instantiated whenever the ClientCacheStorage has enforceEncryption enabled.
	clientCacheKeyEncrypt  ClientCacheKey
	logger                 logr.Logger
	requestCounterVec      *prometheus.CounterVec
	requestErrorCounterVec *prometheus.CounterVec
	revokeOnEvict          bool
	pruneStorageOnEvict    bool
	ctrlClient             ctrlclient.Client
	clientCallbacks        []ClientCallbackHandler
	watcherDoneCh          chan Client
	mu                     sync.RWMutex
	encClientLock          sync.RWMutex
	onceDoWatcher          sync.Once
	watcherCancelFunc      context.CancelFunc
}

// Start method for cachingClientFactory starts the lifetime watcher handler.
func (m *cachingClientFactory) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onceDoWatcher.Do(func() {
		m.startLifetimeWatcherHandler(ctx)
	})
}

// Stop method for cachingClientFactory stops the lifetime watcher handler.
func (m *cachingClientFactory) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.watcherCancelFunc != nil {
		m.watcherCancelFunc()
	}
}

func (m *cachingClientFactory) RegisterClientCallbackHandler(cb ClientCallbackHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientCallbacks = append(m.clientCallbacks, cb)
}

// Prune the storage for the requesting object and CachingClientFactoryPruneRequest.
// Supported, requesting client.Object(s), are: v1beta1.VaultAuth, v1beta1.VaultConnection.
// Then number of pruned storage Secrets will be returned, along with any errors encountered.
// Pruning continues on error, so there is a possibility that only a subset of the requested Secrets will be removed
// from the ClientCacheStorage.
func (m *cachingClientFactory) Prune(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, req CachingClientFactoryPruneRequest) (int, error) {
	if m.isDisabled() {
		return 0, &ClientFactoryDisabledError{}
	}

	var filter ClientCachePruneFilterFunc
	switch cur := obj.(type) {
	case *secretsv1beta1.VaultAuth:
		filter = func(c Client) bool {
			other := c.GetVaultAuthObj()
			return req.FilterFunc(cur, other)
		}
	case *secretsv1beta1.VaultConnection:
		filter = func(c Client) bool {
			other := c.GetVaultConnectionObj()
			return req.FilterFunc(cur, other)
		}
	default:
		return 0, fmt.Errorf("client removal not supported for type %T", cur)
	}

	if !req.PruneStorage {
		return 0, nil
	}
	return m.prune(ctx, client, filter)
}

func (m *cachingClientFactory) prune(ctx context.Context, client ctrlclient.Client, filter ClientCachePruneFilterFunc) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// prune the client cache for filter, pruned is a slice of cache keys
	pruned := m.cache.Prune(filter)
	var errs error
	// for all cache entries pruned, remove the corresponding storage entries.
	if m.storageEnabled() {
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
	c.Close(m.revokeOnEvict)

	if m.storageEnabled() && m.pruneStorageOnEvict {
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

	startTS := time.Now()
	var errs error
	defer func() {
		m.incrementRequestCounter(metrics.OperationRestore, errs)
		clientFactoryOperationTimes.WithLabelValues(subsystemClientFactory, metrics.OperationRestore).Observe(
			time.Since(startTS).Seconds(),
		)
	}()

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

	startTS := time.Now()
	var errs error
	defer func() {
		m.incrementRequestCounter(metrics.OperationRestoreAll, errs)
		clientFactoryOperationTimes.WithLabelValues(subsystemClientFactory, metrics.OperationRestoreAll).Observe(
			time.Since(startTS).Seconds(),
		)
	}()
	req, err := m.restoreAllRequest(ctx, client)
	if err != nil {
		errs = err
		return errs
	}

	entries, err := m.storage.RestoreAll(ctx, client, req)
	if err != nil {
		m.logger.V(consts.LogLevelTrace).Error(err, "RestoreAll failed from storage")
		errs = err
		return errs
	}
	if len(entries) == 0 {
		return nil
	}

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

// ShutDown will attempt to revoke all Client tokens in memory.
// This should be called upon operator deployment deletion if client cache cleanup is required.
func (m *cachingClientFactory) ShutDown(req CachingClientFactoryShutDownRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Shutting down ClientFactory")
	// This will shut down client cache, "blocking" future ClientFactory interface calls
	// NOTE: If a consumer of the client cache factory already has a reference to a client in hand,
	// they may continue using it and generating new tokens/leases.
	m.shutDown = true

	if req.Revoke {
		m.revokeOnEvict = true
		m.pruneStorageOnEvict = true
	} else {
		m.revokeOnEvict = false
		m.pruneStorageOnEvict = false
	}

	m.cache.Purge()
	m.logger.Info("Completed ClientFactory shutdown")
}

func (m *cachingClientFactory) storageEnabled() bool {
	return m.persist && m.storage != nil
}

func (m *cachingClientFactory) isDisabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.shutDown
}

// Get is meant to be called for all resources that require access to Vault.
// It will attempt to fetch a Client from the in-memory cache for the provided Object.
// On a cache miss, an attempt at restoration from storage will be made, if a restoration attempt fails,
// a new Client will be instantiated, and an attempt to login into Vault will be made.
// Upon successful restoration/instantiation/login, the Client will be cached for calls.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func (m *cachingClientFactory) Get(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	logger := log.FromContext(ctx).WithName("cachingClientFactory")
	logger.V(consts.LogLevelDebug).Info("Cache info", "length", m.cache.Len())
	startTS := time.Now()
	var err error
	var cacheKey ClientCacheKey
	var errs error
	defer func() {
		m.incrementRequestCounter(metrics.OperationGet, errs)
		clientFactoryOperationTimes.WithLabelValues(subsystemClientFactory, metrics.OperationGet).Observe(
			time.Since(startTS).Seconds(),
		)
	}()

	if m.isDisabled() {
		errs = errors.Join(&ClientFactoryDisabledError{})
		return nil, errs
	}

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		logger.Error(err, "Failed to get cacheKey from obj")
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		errs = errors.Join(err)
		return nil, errs
	}

	logger = logger.WithValues("cacheKey", cacheKey)
	m.mu.Lock()
	m.mu.Unlock()

	logger.V(consts.LogLevelDebug).Info("Get Client")
	ns, err := common.GetVaultNamespace(obj)
	if err != nil {
		return nil, err
	}

	namespacedClient := func(c Client) (Client, error) {
		// handle the case where the "root" Client's namespace differs from that of the one specified in obj.Spec.Namespace.
		// in which case we cache and return the namespaced Clone of the "root" Client.
		if ns != "" && ns != c.Namespace() {
			cacheKeyClone, err := ClientCacheKeyClone(cacheKey, ns)
			if err != nil {
				return nil, err
			}

			if clone, ok := m.cache.Get(cacheKeyClone); ok {
				return clone, nil
			}

			clone, err := c.Clone(ns)
			if err != nil {
				return nil, err
			}

			logger.Info("Cloned Client",
				"namespace", ns, "cacheKeyClone", cacheKeyClone)
			if _, err := m.cacheClient(ctx, clone, false); err != nil {
				return nil, err
			}

			return clone, nil
		}
		return c, nil
	}

	// try and fetch the client from the in-memory Client cache
	c, ok := m.cache.Get(cacheKey)
	if ok {
		// return the Client from the cache if it is still Valid
		if err := c.Validate(); err == nil {
			return namespacedClient(c)
		}

		logger.V(consts.LogLevelDebug).Error(err, "Invalid client")

		// remove the parent Client from the cache in order to prune any of its clones.
		m.cache.Remove(cacheKey)
	}

	if !ok && m.storageEnabled() {
		// try and restore from Client storage cache, if properly configured to do so.
		restored, err := m.restoreClientFromCacheKey(ctx, client, cacheKey)
		if restored != nil {
			return namespacedClient(restored)
		}

		if !IsStorageEntryNotFoundErr(err) {
			logger.Error(err, "Failed to restore client from storage")
		}
	}

	// if we couldn't produce a valid Client, create a new one, log it in, and cache it
	c, err = NewClientWithLogin(ctx, client, obj, m.clientOptions())
	if err != nil {
		logger.Error(err, "Failed to get NewClientWithLogin")
		errs = errors.Join(err)
		return nil, errs

	}

	// cache the parent Client for future requests.
	cacheKey, err = m.cacheClient(ctx, c, m.storageEnabled())
	if err != nil {
		errs = errors.Join(err)
		return nil, errs

	}

	c, err = namespacedClient(c)
	if err != nil {
		errs = errors.Join(err)
	}

	return c, errs
}

func (m *cachingClientFactory) storeClient(ctx context.Context, client ctrlclient.Client, c Client) error {
	var errs error
	defer func() {
		m.incrementRequestCounter(metrics.OperationStore, errs)
	}()

	if !m.persist || m.storage == nil {
		return fmt.Errorf("storing impossible, storage is not enabled")
	}

	req := ClientCacheStorageStoreRequest{
		Client: c,
		// TODO: make this configurable, since the accessor could be considered to be
		// confidential.
		IncludeTokenAccessor: true,
	}

	if m.encryptionRequired {
		c, err := m.storageEncryptionClient(ctx, client)
		if err != nil {
			errs = errors.Join(err)
			return errs
		}
		authObj := c.GetVaultAuthObj()
		req.EncryptionClient = c
		req.EncryptionVaultAuth = authObj
	}

	if _, err := m.storage.Store(ctx, client, req); err != nil {
		errs = errors.Join(err)
		return errs
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

	c, err := NewClientFromStorageEntry(ctx, client, entry, m.clientOptions())
	if err != nil {
		// remove the Client storage entry if its restoration failed for any reason
		if _, err := m.pruneStorage(ctx, client, entry.CacheKey); err != nil {
			m.logger.Error(err, "Failed to prune cache storage", "entry", entry)
		}

		return nil, err
	}

	if _, err := m.cacheClient(ctx, c, false); err != nil {
		return nil, err
	}

	return c, nil
}

func (m *cachingClientFactory) clientOptions() *ClientOptions {
	return &ClientOptions{
		WatcherDoneCh: m.watcherDoneCh,
	}
}

// cacheClient to the global in-memory cache.
func (m *cachingClientFactory) cacheClient(ctx context.Context, c Client, persist bool) (ClientCacheKey, error) {
	var errs error
	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return "", err
	}

	if _, err := m.cache.Add(c); err != nil {
		m.logger.Error(err, "Failed to added to the cache", "client", c)
		return "", errs
	}
	m.logger.V(consts.LogLevelDebug).Info("Cached the client", "cacheKey", cacheKey, "isClone", c.IsClone())

	if cacheKey == m.clientCacheKeyEncrypt {
		// added protection against persisting the Vault client used for storage
		// data encryption.
		persist = false
	}

	if m.storageEnabled() {
		if persist {
			if err := m.storeClient(ctx, m.ctrlClient, c); err != nil {
				m.logger.Info("Warning: failed to store the client",
					"error", err)
			}
		} else {
			m.logger.Info("Warning: persistence requested but storage not enabled",
				"cacheKey", cacheKey)
		}
	}

	return cacheKey, nil
}

// storageEncryptionClient sets up a Client from a VaultAuth object that supports Transit encryption.
// The result is cached in the ClientCache for future needs. This should only ever be need if the ClientCacheStorage
// has enforceEncryption enabled.
func (m *cachingClientFactory) storageEncryptionClient(ctx context.Context, client ctrlclient.Client) (Client, error) {
	m.encClientLock.Lock()
	defer m.encClientLock.Unlock()

	cached := m.clientCacheKeyEncrypt != ""
	if !cached {
		m.logger.Info("Setting up Vault Client for storage encryption",
			"cacheKey", m.clientCacheKeyEncrypt)
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
		cacheKey, err := m.cacheClient(ctx, vc, false)
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

	if cached {
		// ensure that the cached Vault Client is not expired, and if it is then call storageEncryptionClient() again.
		// This operation should be safe since we are setting m.clientCacheKeyEncrypt to empty string,
		// so there should be no risk of causing a maximum recursion error.
		if reason := c.Validate(); reason != nil {
			m.logger.V(consts.LogLevelWarning).Info("Restored Vault client is invalid, recreating it",
				"cacheKey", m.clientCacheKeyEncrypt, "reason", reason)

			m.cache.Remove(m.clientCacheKeyEncrypt)
			m.clientCacheKeyEncrypt = ""
			return m.storageEncryptionClient(ctx, client)
		}
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

func (m *cachingClientFactory) incrementRequestCounter(operation string, err error) {
	if err != nil {
		m.requestErrorCounterVec.WithLabelValues(operation).Inc()
	} else {
		m.requestCounterVec.WithLabelValues(operation).Inc()
	}
}

func (m *cachingClientFactory) startLifetimeWatcherHandler(ctx context.Context) {
	logger := m.logger.WithName("clientWatcherHandler")
	if m.watcherCancelFunc != nil {
		logger.Info("Already started")
		return
	}

	watcherCtx, cancel := context.WithCancel(ctx)
	m.watcherCancelFunc = cancel

	logger.Info("Starting client lifetime watcher handler")

	go func() {
		if m.watcherDoneCh == nil {
			m.watcherDoneCh = make(chan Client)
		}
		defer close(m.watcherDoneCh)

		for {
			select {
			case <-watcherCtx.Done():
				logger.Info("Client watcher done")
				return
			case c := <-m.watcherDoneCh:
				if c.IsClone() {
					continue
				}

				go func() {
					cacheKey, err := c.GetCacheKey()
					if err != nil {
						logger.Error(err, "Invalid client, client callbacks not executed",
							"cacheKey", cacheKey)
						return
					}

					if m.clientCacheKeyEncrypt == cacheKey {
						m.clientCacheKeyEncrypt = ""
					}

					if err := c.Login(ctx, m.ctrlClient); err != nil {
						logger.Error(err, "Client login failed, client callbacks not executed",
							"cacheKey", cacheKey)
						return
					}

					if _, err := m.cacheClient(ctx, c, true); err != nil {
						logger.Error(err,
							"Failed to cache the client",
							"cacheKey", cacheKey)
					}

					for idx, cbReq := range m.clientCallbacks {
						if cbReq.On != ClientCallbackOnLifetimeWatcherDone {
							continue
						}
						m.logger.Info("Calling client call back",
							"cacheKey", cacheKey, "index", idx)
						cbReq.Callback(ctx, c, nil)
					}
				}()
			}
		}
	}()
}

// NewCachingClientFactory returns a CachingClientFactory with ClientCache initialized.
// The ClientCache's onEvictCallback is registered with the factory's onClientEvict(),
// to ensure any evictions are handled by the factory (this is very important).
func NewCachingClientFactory(ctx context.Context, client ctrlclient.Client, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	factory := &cachingClientFactory{
		storage:            cacheStorage,
		recorder:           config.Recorder,
		persist:            config.Persist,
		ctrlClient:         client,
		watcherDoneCh:      make(chan Client),
		encryptionRequired: config.StorageConfig.EnforceEncryption,
		logger: zap.New().WithName("clientCacheFactory").WithValues(
			"persist", config.Persist,
			"enforceEncryption", config.StorageConfig.EnforceEncryption,
		),
		requestCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientFactoryReqsTotal,
				Help: "Client factory request total",
			}, []string{
				metrics.LabelOperation,
			},
		),
		requestErrorCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientFactoryReqsErrorsTotal,
				Help: "Client factory request errors total",
			}, []string{
				metrics.LabelOperation,
			},
		),
	}

	if config.CollectClientCacheMetrics {
		if config.MetricsRegistry == nil {
			return nil, fmt.Errorf(
				"a MetricsRegistry must be specified when metrics collection is enabled")
		}

		config.MetricsRegistry.MustRegister(
			factory.requestCounterVec,
			factory.requestErrorCounterVec,
			clientFactoryOperationTimes,
		)
	}

	// adds an onEvictCallbackFunc to the ClientCache
	// the function must always call Client.Close() to avoid leaking Go routines
	cache, err := NewClientCache(config.ClientCacheSize, func(key, value interface{}) {
		factory.onClientEvict(ctx, client, key.(ClientCacheKey), value.(Client))
	}, config.MetricsRegistry)
	if err != nil {
		return nil, err
	}

	if config.CollectClientCacheMetrics {
		ctrlmetrics.Registry.MustRegister(newClientCacheCollector(cache, config.ClientCacheSize))
	}

	factory.cache = cache
	factory.Start(ctx)
	return factory, nil
}

// CachingClientFactoryConfig provides the configuration for a CachingClientFactory instance.
type CachingClientFactoryConfig struct {
	RevokeTokensOnUninstall   bool
	Persist                   bool
	StorageConfig             *ClientCacheStorageConfig
	ClientCacheSize           int
	CollectClientCacheMetrics bool
	Recorder                  record.EventRecorder
	MetricsRegistry           prometheus.Registerer
	PruneStorageOnEvict       bool
}

// DefaultCachingClientFactoryConfig provides the default configuration for a CachingClientFactory instance.
func DefaultCachingClientFactoryConfig() *CachingClientFactoryConfig {
	return &CachingClientFactoryConfig{
		StorageConfig:       DefaultClientCacheStorageConfig(),
		ClientCacheSize:     10000,
		Recorder:            &nullEventRecorder{},
		MetricsRegistry:     ctrlmetrics.Registry,
		PruneStorageOnEvict: true,
	}
}

// InitCachingClientFactory initializes a CachingClientFactory along with its ClientCacheStorage.
// It is meant to be called from main.
func InitCachingClientFactory(ctx context.Context, client ctrlclient.Client, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	// TODO: add support for bulk restoration
	logger := zap.New().WithName("initCachingClientFactory")
	logger.Info("Initializing the CachingClientFactory")

	var metricsRegistry prometheus.Registerer
	if config.CollectClientCacheMetrics {
		// register the ClientCache's metrics with the default registry.
		metricsRegistry = ctrlmetrics.Registry
	}
	clientCacheStorage, err := NewDefaultClientCacheStorage(ctx, client, config.StorageConfig, metricsRegistry)
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
