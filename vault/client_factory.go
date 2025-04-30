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
	"k8s.io/utils/keymutex"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/credentials"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

var defaultSetupEncryptionClientTimeout = 90 * time.Second

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
	revokeOnEvict          bool
	pruneStorageOnEvict    bool
	ctrlClient             ctrlclient.Client
	clientCallbacks        []ClientCallbackHandler
	callbackHandlerCh      chan *ClientCallbackHandlerRequest
	mu                     sync.RWMutex
	onceDoWatcher          sync.Once
	callbackHandlerCancel  context.CancelFunc
	// clientMutex is a mutex that is used to lock the client factory's cache by ClientCacheKey.
	clientMutex keymutex.KeyMutex
	// encClientLock is a lock for the encryption client. It is used to ensure that
	// only one encryption client is created. This is necessary because the
	// encryption client is not stored in the cache.
	encClientLock sync.RWMutex
	// encClientSetupTimeout is the timeout for setting up the encryption client.
	// This is used to prevent the factory from blocking indefinitely when setting
	// up the encryption client. It defaults to 90 seconds.
	encClientSetupTimeout time.Duration
	// GlobalVaultAuthOptions is a struct that contains global VaultAuth options.
	GlobalVaultAuthOptions *common.GlobalVaultAuthOptions
	// credentialProviderFactory is a function that returns a CredentialProvider.
	credentialProviderFactory credentials.CredentialProviderFactory
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

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj, m.clientOptions())
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
	if m.isDisabled() {
		return nil, &ClientFactoryDisabledError{}
	}

	logger := log.FromContext(ctx).WithName("cachingClientFactory")
	logger.V(consts.LogLevelTrace).Info("Cache info", "length", m.cache.Len())
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

	cacheKey, err = ComputeClientCacheKeyFromObj(ctx, client, obj, m.clientOptions())
	if err != nil {
		logger.Error(err, "Failed to get cacheKey from obj")
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
			"Failed to get cacheKey from obj, err=%s", err)
		errs = errors.Join(err)
		return nil, errs
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	cacheKeyForLock := cacheKey.String()
	m.clientMutex.LockKey(cacheKeyForLock)
	defer func() {
		if err := m.clientMutex.UnlockKey(cacheKeyForLock); err != nil {
			logger.Error(err, "Failed to unlock client mutex")
		}
	}()

	logger = logger.WithValues("cacheKey", cacheKey)
	logger.V(consts.LogLevelTrace).Info("Got lock")
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
		tainted := c.Tainted()
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
	logger := log.FromContext(ctx).WithName("getClientCacheStorageEntry").WithValues("cacheKey", cacheKey)
	logger.V(consts.LogLevelDebug).Info("Get ClientCacheStorageEntry")
	req := ClientCacheStorageRestoreRequest{
		SecretObjKey: types.NamespacedName{
			Namespace: common.OperatorNamespace,
			Name:      fmt.Sprintf("%s%s", NamePrefixVCC, cacheKey),
		},
		CacheKey: cacheKey,
	}

	if m.encryptionRequired {
		logger.V(consts.LogLevelDebug).Info("Getting encryption client")
		c, err := m.storageEncryptionClient(ctx, client)
		if err != nil {
			return nil, err
		}
		logger.V(consts.LogLevelDebug).Info("Got encryption client")
		authObj := c.GetVaultAuthObj()
		req.DecryptionClient = c
		req.DecryptionVaultAuth = authObj
	}

	logger.V(consts.LogLevelDebug).Info("Restoring from storage")
	return m.storage.Restore(ctx, client, req)
}

func (m *cachingClientFactory) restoreClientFromCacheKey(ctx context.Context, client ctrlclient.Client, cacheKey ClientCacheKey) (Client, error) {
	log.FromContext(ctx).WithName("restoreClientFromCacheKey").V(consts.LogLevelDebug).Info(
		"Restoring client from cache", "cacheKey", cacheKey)
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

	log.FromContext(ctx).WithName("restoreClient").V(consts.LogLevelDebug).Info(
		"Restoring client from cache", "entry", entry)
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
		WatcherDoneCh:             m.callbackHandlerCh,
		GlobalVaultAuthOptions:    m.GlobalVaultAuthOptions,
		CredentialProviderFactory: m.credentialProviderFactory,
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

	if persist && cacheKey == m.clientCacheKeyEncrypt {
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
	logger := log.FromContext(ctx).WithName("storageEncryptionClient")

	if client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	logger.V(consts.LogLevelDebug).Info("Getting Vault Client for storage encryption")

	if m.clientCacheKeyEncrypt == "" {
		return m.setEncryptionClient(ctx, client)
	}

	var err error
	c, ok := m.cache.Get(m.clientCacheKeyEncrypt)
	if !ok {
		c, err = m.setEncryptionClient(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	if reason := c.Validate(ctx); reason != nil {
		logger.V(consts.LogLevelWarning).Info("Restored Vault client is invalid, recreating it",
			"cacheKey", m.clientCacheKeyEncrypt, "reason", reason)

		c, err = m.setEncryptionClient(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// setEncryptionClient sets up a Client for storage encryption.
func (m *cachingClientFactory) setEncryptionClient(ctx context.Context, client ctrlclient.Client) (Client, error) {
	var err error
	m.encClientLock.Lock()

	doneCh := make(chan Client, 1)
	errCh := make(chan error, 1)

	var timeout time.Duration
	if m.encClientSetupTimeout.Seconds() <= 0 {
		timeout = defaultSetupEncryptionClientTimeout
	} else {
		timeout = m.encClientSetupTimeout
	}
	// set a context with a timeout for the encryption client setup, this is to
	// prevent the setup from blocking indefinitely. Typically, we should never hit
	// this timeout, since the Vault client request already has a timeout set.
	ctx_, cancel := context.WithTimeout(ctx, timeout)
	defer func() {
		cancel()
		if err != nil {
			if m.clientCacheKeyEncrypt != "" {
				m.cache.Remove(m.clientCacheKeyEncrypt)
				m.clientCacheKeyEncrypt = ""
			}
		}
		m.encClientLock.Unlock()
		close(doneCh)
		close(errCh)
	}()

	logger := log.FromContext(ctx).WithName("setEncryptionClient")
	go func() {
		var c Client
		var err error
		defer func() {
			if err != nil {
				errCh <- err
			} else {
				doneCh <- c
			}
		}()

		logger.V(consts.LogLevelTrace).Info("Setting up Vault Client for storage encryption",
			"cacheKey", m.clientCacheKeyEncrypt)
		encryptionVaultAuth, err := common.FindVaultAuthForStorageEncryption(ctx, client)
		if err != nil {
			logger.Error(err, "Failed to find VaultAuth for storage encryption")
			if m.clientCacheKeyEncrypt != "" {
				m.cache.Remove(m.clientCacheKeyEncrypt)
				m.clientCacheKeyEncrypt = ""
			}
			return
		}

		c, err = NewClientWithLogin(ctx, client, encryptionVaultAuth, &ClientOptions{
			CredentialProviderFactory: m.credentialProviderFactory,
		})
		if err != nil {
			logger.Error(err, "Failed to create Vault client for storage encryption")
			return
		}

		// cache the new Client for future requests.
		var cacheKey ClientCacheKey
		cacheKey, err = m.cacheClient(ctx, c, false)
		if err != nil {
			return
		}

		if m.clientCacheKeyEncrypt != "" && m.clientCacheKeyEncrypt != cacheKey {
			logger.V(consts.LogLevelTrace).Info("Replacing old encryption client",
				"oldCacheKey", m.clientCacheKeyEncrypt, "newCacheKey", cacheKey)
			m.cache.Remove(m.clientCacheKeyEncrypt)
		}

		m.clientCacheKeyEncrypt = cacheKey
		logger.V(consts.LogLevelTrace).Info("Successfully setup Vault Client for storage encryption",
			"cacheKey", m.clientCacheKeyEncrypt)
		doneCh <- c
	}()

	select {
	case <-ctx_.Done():
		err = ctx_.Err()
		if err != nil {
			err = fmt.Errorf("setup timed out after %s: %w", timeout, err)
		}
		return nil, err
	case err = <-errCh:
		err = fmt.Errorf("failed to setup encryption client: %w", err)
		return nil, err
	case c := <-doneCh:
		return c, nil
	}
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

				cacheKey, err := req.Client.GetCacheKey()
				if err != nil {
					logger.Error(err, "Invalid client, client callbacks not executed",
						"cacheKey", cacheKey)
					continue
				}

				if cacheKey.IsClone() {
					parentCacheKey, err := cacheKey.Parent()
					if err != nil {
						logger.Error(err, "Invalid client clone, client callbacks not executed",
							"cacheKey", cacheKey)
						continue
					}
					cacheKey = parentCacheKey
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

// NewCachingClientFactory returns a CachingClientFactory with ClientCache initialized.
// The ClientCache's onEvictCallback is registered with the factory's onClientEvict(),
// to ensure any evictions are handled by the factory (this is very important).
func NewCachingClientFactory(ctx context.Context, client ctrlclient.Client, cacheStorage ClientCacheStorage, config *CachingClientFactoryConfig) (CachingClientFactory, error) {
	factory := &cachingClientFactory{
		storage:                   cacheStorage,
		recorder:                  config.Recorder,
		persist:                   config.Persist,
		ctrlClient:                client,
		callbackHandlerCh:         make(chan *ClientCallbackHandlerRequest),
		encryptionRequired:        config.StorageConfig.EnforceEncryption,
		encClientSetupTimeout:     config.SetupEncryptionClientTimeout,
		clientMutex:               keymutex.NewHashed(config.ClientCacheNumLocks),
		GlobalVaultAuthOptions:    config.GlobalVaultAuthOptions,
		credentialProviderFactory: config.CredentialProviderFactory,
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
	RevokeTokensOnUninstall      bool
	Persist                      bool
	StorageConfig                *ClientCacheStorageConfig
	ClientCacheSize              int
	CollectClientCacheMetrics    bool
	Recorder                     record.EventRecorder
	MetricsRegistry              prometheus.Registerer
	PruneStorageOnEvict          bool
	GlobalVaultAuthOptions       *common.GlobalVaultAuthOptions
	CredentialProviderFactory    credentials.CredentialProviderFactory
	SetupEncryptionClientTimeout time.Duration
	// ClientCacheNumLocks is the number of locks to allocate for Client Get() and Remove()
	// operations. A higher number of locks will reduce contention but increase
	// memory usage.
	ClientCacheNumLocks int
}

// DefaultCachingClientFactoryConfig provides the default configuration for a CachingClientFactory instance.
func DefaultCachingClientFactoryConfig() *CachingClientFactoryConfig {
	return &CachingClientFactoryConfig{
		StorageConfig:                DefaultClientCacheStorageConfig(),
		ClientCacheSize:              10000,
		Recorder:                     &nullEventRecorder{},
		MetricsRegistry:              ctrlmetrics.Registry,
		PruneStorageOnEvict:          true,
		CredentialProviderFactory:    credentials.NewCredentialProviderFactory(),
		SetupEncryptionClientTimeout: defaultSetupEncryptionClientTimeout,
		ClientCacheNumLocks:          100,
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
