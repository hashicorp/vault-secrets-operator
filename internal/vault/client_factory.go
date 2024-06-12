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
type ClientCallbackOn uint32

const (
	NamePrefixVCC = "vso-cc-"

	// ClientCallbackOnLifetimeWatcherDone is a ClientCallbackOn that handles client
	// lifetime watcher done events.
	ClientCallbackOnLifetimeWatcherDone ClientCallbackOn = 1 << iota
	// ClientCallbackOnCacheRemoval is a ClientCallbackOn that handles client cache removal events.
	ClientCallbackOnCacheRemoval
)

// defaultPruneOrphanAge is the default age at which orphaned clients are
// eligible for pruning.
var defaultPruneOrphanAge = 1 * time.Minute

func (o ClientCallbackOn) String() string {
	switch o {
	case ClientCallbackOnLifetimeWatcherDone:
		return "LifetimeWatcherDone"
	case ClientCallbackOnCacheRemoval:
		return "CacheRemoval"
	default:
		return "Unknown"
	}
}

// ClientCallbackHandlerRequest is a struct that contains a ClientCallbackOn
// enumeration and a Client. It is used to send requests to the
// ClientCallbackHandler. The ClientCallbackHandler will call the ClientCallback
// function with the Client and the ClientCallbackOn enumeration. On is the event
// that occurred, and Client is the Client that the event occurred on. On is
// applied as a bitmask, so multiple events can be sent in a single request.
// For example:
// Setting On = ClientCallbackOnLifetimeWatcherDone | ClientCallbackOnCacheRemoval
// would match either event.
type ClientCallbackHandlerRequest struct {
	On     ClientCallbackOn
	Client Client
}

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
	UnregisterObjectRef(context.Context, ctrlclient.Object) error
}

// clientCacheObjectFilterFunc provides a way to selectively prune  CachingClientFactory's Client cache.
type clientCacheObjectFilterFunc func(cur, other ctrlclient.Object) bool

type CachingClientFactoryPruneRequest struct {
	FilterFunc   clientCacheObjectFilterFunc
	PruneStorage bool
	// SkipClientCallbacks will prevent the ClientCallbackHandlers from being called
	// when a Client is pruned.
	SkipClientCallbacks bool
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
	taintedClientGauge     *prometheus.GaugeVec
	revokeOnEvict          bool
	pruneStorageOnEvict    bool
	ctrlClient             ctrlclient.Client
	clientCallbacks        []ClientCallbackHandler
	callbackHandlerCh      chan *ClientCallbackHandlerRequest
	mu                     sync.RWMutex
	onceDoWatcher          sync.Once
	callbackHandlerCancel  context.CancelFunc
	// clientLocksLock is a lock for the clientLocks map.
	clientLocksLock sync.RWMutex
	// clientLocks is a map of cache keys to locks that allow for concurrent access
	// to the client factory's cache.
	clientLocks map[ClientCacheKey]*sync.RWMutex
	// encClientLock is a lock for the encryption client. It is used to ensure that
	// only one encryption client is created. This is necessary because the
	// encryption client is not stored in the cache.
	encClientLock sync.RWMutex
	// orphanPrunerCancel is a function that is used to cancel the orphan client pruner.
	orphanPrunerCancel context.CancelFunc
	// orphanPrunerClientCh is a channel that is used to handle Clients that no longer
	// have any object references.
	orphanPrunerClientCh chan Client
}

// UnregisterObjectRef removes the reference to the object with the specified
// UID. This is used to remove the reference to the object when it is deleted.
// All controllers should call this method if they are using the caching client
// factory.
func (m *cachingClientFactory) UnregisterObjectRef(ctx context.Context, o ctrlclient.Object) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	logger := log.FromContext(ctx).WithName("UnregisterObjectRef").WithValues(
		"uid", o.GetUID(),
	)

	vaultClientMeta, err := getVaultClientMeta(o)
	if err != nil {
		return err
	}

	cacheKey := ClientCacheKey(vaultClientMeta.CacheKey)
	logger.V(consts.LogLevelDebug).Info("Unregistering client reference",
		"vaultClientMeta", vaultClientMeta)
	if c, ok := m.cache.Get(cacheKey); ok && c.Stat() != nil {
		lastRefCount := c.Stat().DecRefCount()
		logger.V(consts.LogLevelDebug).Info("Writing to orphanPrunerClientCh",
			"id", c.ID(), "cacheKey", cacheKey, "lastRefCount", lastRefCount, "refCount", c.Stat().RefCount(),
		)
		m.orphanPrunerClientCh <- c
	}

	return nil
}

// Start method for cachingClientFactory starts the lifetime watcher handler.
func (m *cachingClientFactory) Start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onceDoWatcher.Do(func() {
		m.startClientCallbackHandler(ctx)
		m.startOrphanClientPruner(ctx)
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

	return m.prune(ctx, client, filter, req.SkipClientCallbacks)
}

func (m *cachingClientFactory) prune(ctx context.Context, client ctrlclient.Client, filter ClientCachePruneFilterFunc, skipCallbacks bool) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// prune the client cache for filter, pruned is a slice of cache keys
	pruned := m.cache.Prune(filter)
	var errs error
	if !skipCallbacks {
		for _, c := range pruned {
			// the callback handler will remove the client from the storage
			m.callbackHandlerCh <- &ClientCallbackHandlerRequest{
				On:     ClientCallbackOnCacheRemoval,
				Client: c,
			}
		}
	} else {
		// for all cache entries pruned, remove the corresponding storage entries.
		if m.storageEnabled() {
			for _, c := range pruned {
				key, _ := c.GetCacheKey()
				if _, err := m.pruneStorage(ctx, client, key); err != nil {
					errs = errors.Join(errs, err)
				}
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
	logger := m.logger.WithName("onClientEvict").WithValues("cacheKey", cacheKey)
	logger.V(consts.LogLevelDebug).Info("Handling client cache eviction")
	c.Close(m.revokeOnEvict)

	if m.clientCacheKeyEncrypt == cacheKey {
		m.clientCacheKeyEncrypt = ""
	}

	if m.storageEnabled() && m.pruneStorageOnEvict {
		if count, err := m.pruneStorage(ctx, client, cacheKey); err != nil {
			logger.Error(err, "Failed to remove Client from storage")
		} else {
			logger.V(consts.LogLevelDebug).Info("Pruned storage", "count", count)
		}
	}

	m.removeClientLock(cacheKey)
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

func (m *cachingClientFactory) clientLock(cacheKey ClientCacheKey) (*sync.RWMutex, bool) {
	m.clientLocksLock.Lock()
	defer m.clientLocksLock.Unlock()
	lock, ok := m.clientLocks[cacheKey]
	if !ok {
		lock = &sync.RWMutex{}
		m.clientLocks[cacheKey] = lock
	}
	return lock, ok
}

func (m *cachingClientFactory) removeClientLock(cacheKey ClientCacheKey) {
	m.clientLocksLock.Lock()
	defer m.clientLocksLock.Unlock()
	delete(m.clientLocks, cacheKey)
}

// Get is meant to be called for all resources that require access to Vault.
// It will attempt to fetch a Client from the in-memory cache for the provided Object.
// On a cache miss, an attempt at restoration from storage will be made, if a restoration attempt fails,
// a new Client will be instantiated, and an attempt to login into Vault will be made.
// Upon successful restoration/instantiation/login, the Client will be cached for calls.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func (m *cachingClientFactory) Get(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	if m.isDisabled() {
		return nil, &ClientFactoryDisabledError{}
	}

	logger := log.FromContext(ctx).WithName("cachingClientFactory")
	logger.V(consts.LogLevelDebug).Info("Cache info", "length", m.cache.Len())
	startTS := time.Now()
	var err error
	var cacheKey ClientCacheKey
	var errs error
	var tainted bool
	var clientMeta *secretsv1beta1.VaultClientMeta
	defer func() {
		m.incrementRequestCounter(metrics.OperationGet, errs)
		clientFactoryOperationTimes.WithLabelValues(subsystemClientFactory, metrics.OperationGet).Observe(
			time.Since(startTS).Seconds(),
		)

		mt := m.taintedClientGauge.WithLabelValues(
			metrics.OperationGet, cacheKey.String(),
		)
		if tainted {
			mt.Set(1)
		} else {
			mt.Set(0)
		}

		if clientMeta != nil {
			m.updateClientStatsAfterGet(ctx, cacheKey, clientMeta, errs)
		}
	}()

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj)
	if err != nil {
		logger.Error(err, "Failed to get cacheKey from obj")
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		errs = errors.Join(err)
		return nil, errs
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	lock, cachedLock := m.clientLock(cacheKey)
	lock.Lock()
	defer lock.Unlock()

	clientMeta, err = getVaultClientMeta(obj)
	if err != nil {
		errs = errors.Join(errs, err)
		return nil, errs
	}

	logger = logger.WithValues("cacheKey", cacheKey)
	logger.V(consts.LogLevelDebug).Info("Got lock",
		"numLocks", len(m.clientLocks),
		"cachedLock", cachedLock,
	)

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
		tainted = c.Tainted()
		logger.V(consts.LogLevelTrace).Info("Got client from cache",
			"clientID", c.ID(), "tainted", tainted)
		if err := c.Validate(ctx); err != nil {
			logger.V(consts.LogLevelDebug).Error(err, "Invalid client",
				"tainted", tainted)
			m.cache.Remove(cacheKey)
			m.callbackHandlerCh <- &ClientCallbackHandlerRequest{
				On:     ClientCallbackOnCacheRemoval,
				Client: c,
			}
		} else {
			c.Untaint()
			return namespacedClient(c)
		}
	} else {
		logger.V(consts.LogLevelTrace).Info("Client not found in cache", "cacheKey", fmt.Sprintf("%#v", cacheKey))
		if m.storageEnabled() {
			// try and restore from Client storage cache, if properly configured to do so.
			restored, err := m.restoreClientFromCacheKey(ctx, client, cacheKey)
			if restored != nil {
				return namespacedClient(restored)
			}

			if !IsStorageEntryNotFoundErr(err) {
				logger.Error(err, "Failed to restore client from storage")
			}
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

func (m *cachingClientFactory) updateClientStatsAfterGet(ctx context.Context, cacheKey ClientCacheKey,
	clientMeta *secretsv1beta1.VaultClientMeta, errs error,
) {
	logger := log.FromContext(ctx).WithName("updateClientStatsAfterGet").WithValues(
		"cacheKey", cacheKey,
		"clientMeta", clientMeta,
	)
	if clientMeta == nil {
		logger.V(consts.LogLevelTrace).Info("Skipping status update, client meta is nil")
		return
	}

	lastCacheKey := ClientCacheKey(clientMeta.CacheKey)
	var incrementReason string
	var decrementReason string
	logger.Info("Update client stats", "clientMeta", clientMeta)
	switch {
	// previous get errors
	case errs != nil:
		decrementReason = "errorOnGet"
	case lastCacheKey == "" && cacheKey != "":
		incrementReason = "newReference"
	case lastCacheKey != cacheKey:
		decrementReason = "cacheKeyChange"
		incrementReason = "cacheKeyChange"
	default:
		if !clientMeta.CreationTimestamp.IsZero() {
			c, ok := m.cache.Get(cacheKey)
			if ok && c.Stat().CreationTimestamp().Unix() != clientMeta.CreationTimestamp.Unix() {
				incrementReason = "creationTimestampChange"
			}
		}
	}
	if decrementReason == "" && incrementReason == "" {
		logger.V(consts.LogLevelTrace).Info("Skipping ref count update, not required")
		return
	}

	if decrementReason != "" && lastCacheKey != "" {
		if c, ok := m.cache.Get(lastCacheKey); ok {
			lastRefCount := c.Stat().DecRefCount()
			logger.V(consts.LogLevelDebug).Info("Decrement ref count on err",
				"lastRefCount", lastRefCount,
				"refCount", c.Stat().RefCount(),
				"creationTimestamp", c.Stat().CreationTimestamp(),
				"reason", decrementReason,
			)
			// send the client to the cache pruner.
			m.orphanPrunerClientCh <- c
		}
	}

	if incrementReason != "" {
		if c, ok := m.cache.Get(cacheKey); ok {
			lastRefCount := c.Stat().IncRefCount()
			logger.V(consts.LogLevelDebug).Info("Increment ref count",
				"lastRefCount", lastRefCount,
				"refCount", c.Stat().RefCount(),
				"creationTimestamp", c.Stat().CreationTimestamp(),
				"reason", incrementReason,
			)
		}
	}
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
		if reason := c.Validate(ctx); reason != nil {
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
	logger := log.FromContext(ctx).WithName("clientCallbackHandler")
	if m.callbackHandlerCancel != nil {
		logger.Info("Already started")
		return
	}

	callbackCtx, cancel := context.WithCancel(ctx)
	m.callbackHandlerCancel = cancel

	logger.Info("Starting client callback handler")

	go func() {
		if m.callbackHandlerCh == nil {
			m.callbackHandlerCh = make(chan *ClientCallbackHandlerRequest)
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
			case req, stillOpen := <-m.callbackHandlerCh:
				if !stillOpen {
					logger.Info("Client callback handler channel closed")
					return
				}
				if req == nil {
					continue
				}

				if req.Client.IsClone() {
					continue
				}

				cacheKey, err := req.Client.GetCacheKey()
				if err != nil {
					logger.Error(err, "Invalid client, client callbacks not executed",
						"cacheKey", cacheKey)
					continue
				}

				// remove the client from the cache, it will be recreated when a reconciler
				// requests it.
				logger.V(consts.LogLevelDebug).Info("Removing client from cache", "cacheKey", cacheKey)
				if req.On&ClientCallbackOnLifetimeWatcherDone != 0 {
					m.cache.Remove(cacheKey)
					if m.storageEnabled() {
						if _, err := m.pruneStorage(ctx, m.ctrlClient, cacheKey); err != nil {
							logger.Info("Warning: failed to prune storage", "cacheKey", cacheKey)
						}
					}
				}

				m.callClientCallbacks(ctx, req.Client, req.On, false)
			}
		}
	}()
}

// callClientCallbacks calls all registered client callbacks for the specified
// event. If wait is true, it will block until all callbacks have been executed.
// Note: wait is only for testing purposes.
func (m *cachingClientFactory) callClientCallbacks(ctx context.Context, c Client, on ClientCallbackOn, wait bool) {
	logger := log.FromContext(ctx).WithName("callClientCallbacks")

	var cbs []ClientCallbackHandler
	for _, cbReq := range m.clientCallbacks {
		x := on & cbReq.On
		if x != 0 {
			cbs = append(cbs, cbReq)
			continue
		}
	}

	if len(cbs) == 0 {
		return
	}

	var wg sync.WaitGroup
	if wait {
		wg.Add(len(cbs))
	}

	for idx, cbReq := range cbs {
		logger.Info("Calling client callback",
			"index", idx, "clientID", c.ID(), "on", on)
		// call in a go routine to avoid blocking the channel
		go func(cbReq ClientCallbackHandler) {
			if wait {
				defer wg.Done()
			}
			cbReq.Callback(ctx, c)
		}(cbReq)
	}

	if wait {
		wg.Wait()
	}
}

// startOrphanClientPruner starts a go routine that will periodically prune
// orphaned clients from the cache. An orphaned client is a client that is not
// associated with any of secretsv1beta1.VaultStaticSecret,
// secretsv1beta1.VaultPKISecret, secretsv1beta1.VaultDynamicSecret.
func (m *cachingClientFactory) startOrphanClientPruner(ctx context.Context) {
	logger := log.FromContext(ctx).WithName("orphanClientPruner")
	if m.orphanPrunerCancel != nil {
		logger.Info("Already started")
	}

	if m.orphanPrunerClientCh == nil {
		m.orphanPrunerClientCh = make(chan Client)
	}

	ctx_, cancel := context.WithCancel(ctx)
	m.orphanPrunerCancel = cancel
	// TODO: make period a command line option
	ticker := time.NewTicker(30 * time.Minute)
	go func() {
		defer func() {
			close(m.orphanPrunerClientCh)
			m.orphanPrunerCancel = nil
		}()
		for {
			select {
			case <-ctx_.Done():
				logger.Info("Done")
				return

			case c, stillOpen := <-m.orphanPrunerClientCh:
				if !stillOpen {
					logger.Info("Client callback handler channel closed")
					return
				}

				if c.Stat() == nil {
					continue
				}

				if c.Stat().RefCount() <= 0 {
					cacheKey, err := c.GetCacheKey()
					if err != nil {
						logger.Error(err, "Prune orphan Vault Clients", "trigger", "wakeup")
					} else {
						logger.Info("Prune orphan Vault Clients", "refCount", c.Stat().RefCount(), "trigger", "wakeup")
						m.cache.Remove(cacheKey)
					}
				}
			case <-ticker.C:
				// catch-all for the pruner
				if count, err := m.pruneOrphanClients(ctx); err != nil {
					logger.Error(err, "Prune orphan Vault Clients", "trigger", "tick")
				} else {
					logger.Info("Prune orphan Vault Clients", "count", count, "trigger", "tick")
				}
			}
		}
	}()
}

// pruneOrphanClients will remove all clients from the cache that are not
// associated with any of the following custom resources:
// secretsv1beta1.VaultStaticSecret, secretsv1beta1.VaultPKISecret,
// secretsv1beta1.VaultDynamicSecret.
//
// The function will return the number of clients pruned. No clients will be
// pruned if an error occurs when getting the custom resources.
func (m *cachingClientFactory) pruneOrphanClients(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger := m.logger.WithName("pruneOrphanClients")

	currentClientCacheKeys, err := GetGlobalVaultCacheKeys(ctx, m.ctrlClient)
	if err != nil {
		return 0, err
	}

	var toPrune []ClientCacheKey
	for _, c := range m.cache.Values() {
		key, err := c.GetCacheKey()
		if err != nil {
			continue
		}

		if _, ok := currentClientCacheKeys[key]; !ok {
			if key == m.clientCacheKeyEncrypt {
				continue
			}
			stat := c.Stat()
			if stat == nil {
				continue
			}
			// prune clients that have not been created in the last 5 minutes, this gives
			// time for any referring resource to update their
			// .status.vaultClientMeta.cacheKey
			if stat.Age() >= defaultPruneOrphanAge {
				toPrune = append(toPrune, key)
			}
		}
	}

	// TODO: ensure that this does not block forever...
	var count int
	wg := sync.WaitGroup{}
	wg.Add(len(toPrune))
	for _, key := range toPrune {
		count++
		go func() {
			defer wg.Done()
			m.cache.Remove(key)
		}()
	}
	wg.Wait()

	logger.V(consts.LogLevelDebug).Info(
		"Pruned orphaned clients", "count", count, "pruned", toPrune)
	return count, nil
}

// NewCachingClientFactory returns a CachingClientFactory with ClientCache initialized.
// The ClientCache's onEvictCallback is registered with the factory's onClientEvict(),
// to ensure any evictions are handled by the factory (this is very important).
func NewCachingClientFactory(ctx context.Context, client ctrlclient.Client, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	factory := &cachingClientFactory{
		storage:             cacheStorage,
		recorder:            config.Recorder,
		persist:             config.Persist,
		ctrlClient:          client,
		pruneStorageOnEvict: true,
		callbackHandlerCh:   make(chan *ClientCallbackHandlerRequest),
		encryptionRequired:  config.StorageConfig.EnforceEncryption,
		clientLocks:         make(map[ClientCacheKey]*sync.RWMutex, config.ClientCacheSize),
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
		taintedClientGauge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metricsFQNClientFactoryTaintedClients,
				Help: "Client factory tainted clients",
			}, []string{
				metrics.LabelOperation,
				metrics.LabelCacheKey,
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
			factory.taintedClientGauge,
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

// GetGlobalVaultCacheKeys returns the current set of vault.ClientCacheKey(s) that are in
// use.
func GetGlobalVaultCacheKeys(ctx context.Context, client ctrlclient.Client) (map[ClientCacheKey]int, error) {
	currentClientCacheKeys := map[ClientCacheKey]int{}
	addCurrentClientCacheKeys := func(meta secretsv1beta1.VaultClientMeta) {
		if meta.CacheKey != "" {
			key := ClientCacheKey(meta.CacheKey)
			currentClientCacheKeys[key] = currentClientCacheKeys[key] + 1
		}
	}

	var vssList secretsv1beta1.VaultStaticSecretList
	err := client.List(ctx, &vssList)
	if err != nil {
		return nil, err
	}

	for _, o := range vssList.Items {
		addCurrentClientCacheKeys(o.Status.VaultClientMeta)
	}
	var vpsList secretsv1beta1.VaultPKISecretList
	err = client.List(ctx, &vpsList)
	if err != nil {
		return nil, err
	}
	for _, o := range vpsList.Items {
		addCurrentClientCacheKeys(o.Status.VaultClientMeta)
	}

	var vdsList secretsv1beta1.VaultDynamicSecretList
	err = client.List(ctx, &vdsList)
	if err != nil {
		return nil, err
	}
	for _, o := range vdsList.Items {
		addCurrentClientCacheKeys(o.Status.VaultClientMeta)
	}

	return currentClientCacheKeys, nil
}

// getVaultClientMeta returns the VaultClientMeta for the provided Object. It
// supports these types: VaultStaticSecret, VaultPKISecret, VaultDynamicSecret.
//
// If o is not one of the supported types, an error is returned.
func getVaultClientMeta(o ctrlclient.Object) (*secretsv1beta1.VaultClientMeta, error) {
	switch t := o.(type) {
	case *secretsv1beta1.VaultStaticSecret:
		return &t.Status.VaultClientMeta, nil
	case *secretsv1beta1.VaultPKISecret:
		return &t.Status.VaultClientMeta, nil
	case *secretsv1beta1.VaultDynamicSecret:
		return &t.Status.VaultClientMeta, nil
	default:
		return nil, fmt.Errorf("vault client meta not found for type %T", t)
	}
}
