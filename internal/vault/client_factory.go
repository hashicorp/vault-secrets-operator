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
type ClientCallback func(ctx context.Context, c Client)

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
	callbackHandlerCh      chan Client
	mu                     sync.RWMutex
	onceDoWatcher          sync.Once
	callbackHandlerCancel  context.CancelFunc
}

// Start method for cachingClientFactory starts the lifetime watcher handler.
func (m *cachingClientFactory) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onceDoWatcher.Do(func() {
		m.startClientCallbackHandler(ctx)
	})
}

// Stop method for cachingClientFactory stops the lifetime watcher handler.
func (m *cachingClientFactory) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callbackHandlerCancel != nil {
		m.callbackHandlerCancel()
	}
}

// RegisterClientCallbackHandler registers a ClientCallbackHandler with the
// cachingClientFactory. The ClientCallbackHandler will be called when the
// specified event occurs. There is no duplication detection, so the same handler
// can be registered multiple times. The caller is responsible for ensuring that
// there are no duplicates.
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isDisabled() {
		return nil, &ClientFactoryDisabledError{}
	}

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

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		logger.Error(err, "Failed to get cacheKey from obj")
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		errs = errors.Join(err)
		return nil, errs
	}

	logger = logger.WithValues("cacheKey", cacheKey)
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
		logger.V(consts.LogLevelTrace).Info("Got client from cache", "clientID", c.ID())
		err := c.Validate()
		if err == nil {
			return namespacedClient(c)
		}

		logger.V(consts.LogLevelDebug).Error(err, "Invalid client")

		// remove the parent Client from the cache in order to prune any of its clones.
		m.cache.Remove(cacheKey)
	} else {
		logger.V(consts.LogLevelTrace).Info("Client not found in cache", "cacheKey", fmt.Sprintf("%#v", cacheKey))
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

	logger.V(consts.LogLevelTrace).Info("New client created",
		"cacheKey", cacheKey, "clientID", c.ID())
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
		WatcherDoneCh: m.callbackHandlerCh,
	}
}

// cacheClient to the global in-memory cache.
func (m *cachingClientFactory) cacheClient(ctx context.Context, c Client, persist bool) (ClientCacheKey, error) {
	var errs error
	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return "", err
	}

	logger := log.FromContext(ctx).WithValues("cacheKey", cacheKey, "isClone", c.IsClone())
	if _, ok := m.cache.Get(cacheKey); ok {
		logger.V(consts.LogLevelDebug).Info("Client already cached, removing it", "cacheKey", cacheKey)
		// removal ensures that the eviction handler is called, this should mitigate any
		// potential go routine leaks on the lifetime watcher.
		m.cache.Remove(cacheKey)
	}

	if _, err := m.cache.Add(c); err != nil {
		logger.Error(err, "Failed to add client to the cache")
		return "", errs
	}
	logger.V(consts.LogLevelTrace).Info("Cached the client")

	if cacheKey == m.clientCacheKeyEncrypt {
		// added protection against persisting the Vault client used for storage
		// data encryption.
		logger.Info("Warning: refusing to store the encryption client")
		persist = false
	}

	if m.storageEnabled() {
		if persist {
			if err := m.storeClient(ctx, m.ctrlClient, c); err != nil {
				logger.Info("Warning: failed to store the client",
					"error", err)
			}
		}
	} else if persist {
		logger.Info("Warning: persistence requested but storage not enabled")
	}

	return cacheKey, nil
}

// storageEncryptionClient sets up a Client from a VaultAuth object that supports Transit encryption.
// The result is cached in the ClientCache for future needs. This should only ever be need if the ClientCacheStorage
// has enforceEncryption enabled.
func (m *cachingClientFactory) storageEncryptionClient(ctx context.Context, client ctrlclient.Client) (Client, error) {
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

func (m *cachingClientFactory) incrementRequestCounter(operation string, err error) {
	if err != nil {
		m.requestErrorCounterVec.WithLabelValues(operation).Inc()
	} else {
		m.requestCounterVec.WithLabelValues(operation).Inc()
	}
}

func (m *cachingClientFactory) startClientCallbackHandler(ctx context.Context) {
	if m.callbackHandlerCancel != nil {
		m.logger.Info("Already started")
		return
	}

	callbackCtx, cancel := context.WithCancel(ctx)
	m.callbackHandlerCancel = cancel

	logger := log.FromContext(ctx).WithName("clientCallbackHandler")
	logger.Info("Starting client callback handler")

	go func() {
		if m.callbackHandlerCh == nil {
			m.callbackHandlerCh = make(chan Client)
		}
		defer func() {
			close(m.callbackHandlerCh)
			m.callbackHandlerCh = nil
		}()

		for {
			select {
			case <-callbackCtx.Done():
				logger.Info("Client callback handler done")
				return
			case c, stillOpen := <-m.callbackHandlerCh:
				if !stillOpen {
					logger.Info("Client callback handler channel closed")
					return
				}
				if c.IsClone() {
					continue
				}

				cacheKey, err := c.GetCacheKey()
				if err != nil {
					logger.Error(err, "Invalid client, client callbacks not executed",
						"cacheKey", cacheKey)
					continue
				}

				// remove the client from the cache, it will be recreated when a reconciler
				// requests it.
				logger.V(consts.LogLevelDebug).Info("Removing client from cache", "cacheKey", cacheKey)
				m.cache.Remove(cacheKey)
				if m.storageEnabled() {
					if _, err := m.pruneStorage(ctx, m.ctrlClient, cacheKey); err != nil {
						logger.Info("Warning: failed to prune storage", "cacheKey", cacheKey)
					}
				}

				for idx, cbReq := range m.clientCallbacks {
					if cbReq.On != ClientCallbackOnLifetimeWatcherDone {
						continue
					}

					logger.Info("Calling client callback on lifetime watcher done",
						"index", idx, "cacheKey", cacheKey, "clientID", c.ID())
					// call in a go routine to avoid blocking the channel
					go func(cbReq ClientCallbackHandler) {
						cbReq.Callback(ctx, c)
					}(cbReq)
				}
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
		callbackHandlerCh:  make(chan Client),
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

	return clientCacheFactory, nil
}

var _ record.EventRecorder = (*nullEventRecorder)(nil)

type nullEventRecorder struct {
	record.EventRecorder
}

func (n *nullEventRecorder) Event(_ runtime.Object, _, _, _ string) {}
