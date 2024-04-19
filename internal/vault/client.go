// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault/api"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

type ClientOptions struct {
	SkipRenewal   bool
	WatcherDoneCh chan<- Client
}

func defaultClientOptions() *ClientOptions {
	return &ClientOptions{
		SkipRenewal: false,
	}
}

// NewClient returns a Client specific to obj.
// Supported objects can be found in common.GetVaultAuthAndTarget.
// An error will be returned if obj is deemed to be invalid.
func NewClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, opts *ClientOptions) (Client, error) {
	var authObj *secretsv1beta1.VaultAuth
	var providerNamespace string
	switch t := obj.(type) {
	case *secretsv1beta1.VaultAuth:
		// setting up a new Client is allowed in the case where the VaultAuth has StorageEncryption enabled.
		// The object must also be in the Operator's Namespace.
		authObj = t
		providerNamespace = authObj.Namespace
		if providerNamespace != common.OperatorNamespace {
			return nil, fmt.Errorf("invalid object %T, only allowed in the %s namespace", authObj, common.OperatorNamespace)
		}
		if authObj.Spec.StorageEncryption == nil {
			return nil, fmt.Errorf("invalid object %T, StorageEncryption not configured", t)
		}
	default:
		// otherwise we fall back to the common.GetVaultAuthNamespaced() to decide whether, or not obj is supported.
		a, err := common.GetVaultAuthNamespaced(ctx, client, obj)
		if err != nil {
			return nil, err
		}

		providerNamespace = obj.GetNamespace()
		authObj = a
	}

	connName, err := common.GetConnectionNamespacedName(authObj)
	if err != nil {
		return nil, err
	}

	connObj, err := common.GetVaultConnection(ctx, client, connName)
	if err != nil {
		return nil, err
	}
	c := &defaultClient{}
	if err := c.Init(ctx, client, authObj, connObj, providerNamespace, opts); err != nil {
		return nil, err
	}
	return c, nil
}

// NewClientWithLogin returns a logged-in Client specific to obj.
// Supported objects can be found in common.GetVaultAuthAndTarget.
// An error will be returned if obj is deemed to be invalid.
func NewClientWithLogin(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, opts *ClientOptions) (Client, error) {
	c, err := NewClient(ctx, client, obj, opts)
	if err != nil {
		return nil, err
	}
	if err := c.Login(ctx, client); err != nil {
		return nil, err
	}

	return c, nil
}

// NewClientFromStorageEntry restores a Client from provided clientCacheStorageEntry.
// If the restoration fails an error will be returned.
func NewClientFromStorageEntry(ctx context.Context, client ctrlclient.Client, entry *clientCacheStorageEntry, opts *ClientOptions) (Client, error) {
	authObj, err := common.FindVaultAuthByUID(ctx, client, entry.VaultAuthNamespace,
		entry.VaultAuthUID, entry.VaultAuthGeneration)
	if err != nil {
		return nil, err
	}

	connObj, err := common.FindVaultConnectionByUID(ctx, client, entry.VaultConnectionNamespace,
		entry.VaultConnectionUID, entry.VaultConnectionGeneration)
	if err != nil {
		return nil, err
	}

	c := &defaultClient{}
	if err := c.Init(ctx, client, authObj, connObj, entry.ProviderNamespace, opts); err != nil {
		return nil, err
	}

	if err := c.Restore(ctx, entry.VaultSecret); err != nil {
		return nil, err
	}

	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return nil, err
	}
	if cacheKey != entry.CacheKey {
		return nil, fmt.Errorf("restored client's cacheKey %s does not match expected %s", cacheKey, entry.CacheKey)
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	if _, err := c.Read(ctx, NewReadRequest("auth/token/lookup-self", nil)); err != nil {
		return nil, err
	}

	return c, nil
}

type ClientBase interface {
	Read(context.Context, ReadRequest) (Response, error)
	Write(context.Context, WriteRequest) (Response, error)
	ID() string
}

type Client interface {
	ClientBase
	Init(context.Context, ctrlclient.Client, *secretsv1beta1.VaultAuth, *secretsv1beta1.VaultConnection, string, *ClientOptions) error
	Login(context.Context, ctrlclient.Client) error
	Restore(context.Context, *api.Secret) error
	GetTokenSecret() *api.Secret
	CheckExpiry(int64) (bool, error)
	Validate() error
	GetVaultAuthObj() *secretsv1beta1.VaultAuth
	GetVaultConnectionObj() *secretsv1beta1.VaultConnection
	GetCredentialProvider() provider.CredentialProviderBase
	GetCacheKey() (ClientCacheKey, error)
	Close(bool)
	Clone(string) (Client, error)
	IsClone() bool
	Namespace() string
	SetNamespace(string)
}

var _ Client = (*defaultClient)(nil)

type defaultClient struct {
	client             *api.Client
	isClone            bool
	authObj            *secretsv1beta1.VaultAuth
	connObj            *secretsv1beta1.VaultConnection
	authSecret         *api.Secret
	skipRenewal        bool
	lastRenewal        int64
	targetNamespace    string
	credentialProvider provider.CredentialProviderBase
	watcher            *api.LifetimeWatcher
	inClosing          bool
	closed             bool
	lastWatcherErr     error
	watcherDoneCh      chan<- Client
	once               sync.Once
	mu                 sync.RWMutex
	id                 string
}

// Validate the client, returning an error for any validation failures.
// Typically, an invalid Client would be discarded and replaced with a new
// instance.
func (c *defaultClient) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.authSecret == nil {
		return fmt.Errorf("auth secret not set, never logged in")
	}

	if !c.skipRenewal {
		if c.lastWatcherErr != nil {
			return c.lastWatcherErr
		}
		if c.watcher == nil {
			return errors.New("lifetime watcher not set")
		}
	}

	if expired, err := c.checkExpiry(0); expired || err != nil {
		return errors.New("client token expired")
	}

	return nil
}

func (c *defaultClient) IsClone() bool {
	return c.isClone
}

func (c *defaultClient) Namespace() string {
	return c.client.Namespace()
}

func (c *defaultClient) SetNamespace(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.client.SetNamespace(s)
}

func (c *defaultClient) Clone(namespace string) (Client, error) {
	if namespace == "" {
		return nil, errors.New("namespace cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	clone, err := c.client.Clone()
	if err != nil {
		return nil, err
	}

	client := &defaultClient{
		client:             clone,
		isClone:            true,
		authObj:            c.authObj,
		connObj:            c.connObj,
		authSecret:         c.authSecret,
		skipRenewal:        true,
		targetNamespace:    c.targetNamespace,
		credentialProvider: c.credentialProvider,
	}
	client.SetNamespace(namespace)

	return client, nil
}

func (c *defaultClient) GetCredentialProvider() provider.CredentialProviderBase {
	return c.credentialProvider
}

func (c *defaultClient) GetCacheKey() (ClientCacheKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getCacheKey()
}

func (c *defaultClient) getCacheKey() (ClientCacheKey, error) {
	cacheKey, err := ComputeClientCacheKeyFromClient(c)
	if err != nil {
		return "", err
	}

	if c.IsClone() {
		cacheKey = ClientCacheKey(fmt.Sprintf("%s-%s", cacheKey, c.Namespace()))
	}

	return cacheKey, nil
}

// Restore self from the provided api.Secret (should have an Auth configured).
// The provided Client Token will be renewed as well.
func (c *defaultClient) Restore(ctx context.Context, secret *api.Secret) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.watcher != nil {
		c.watcher.Stop()
	}

	if secret == nil {
		return fmt.Errorf("api.Secret is nil")
	}

	if secret.Auth == nil {
		return fmt.Errorf("not an auth secret")
	}

	c.authSecret = secret
	c.client.SetToken(secret.Auth.ClientToken)

	id, err := c.hashAccessor()
	if err != nil {
		return err
	}

	c.id = id

	if secret.Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (c *defaultClient) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth,
	connObj *secretsv1beta1.VaultConnection, providerNamespace string, opts *ClientOptions,
) error {
	var err error
	c.once.Do(func() {
		if opts == nil {
			opts = defaultClientOptions()
		}

		err = c.init(ctx, client, authObj, connObj, providerNamespace, opts)
	})

	return err
}

func (c *defaultClient) getTokenTTL() (time.Duration, error) {
	return c.authSecret.TokenTTL()
}

func (c *defaultClient) CheckExpiry(offset int64) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.authSecret == nil || c.lastRenewal == 0 {
		return false, fmt.Errorf("cannot check client token expiry, never logged in")
	}

	return c.checkExpiry(offset)
}

func (c *defaultClient) checkExpiry(offset int64) (bool, error) {
	ttl, err := c.getTokenTTL()
	if err != nil {
		return false, err
	}

	horizon := ttl - time.Second*time.Duration(offset)
	if horizon < 1 {
		// will always result in expiry
		return true, nil
	}

	ts := time.Unix(c.lastRenewal, 0).Add(horizon)
	return time.Now().After(ts), nil
}

func (c *defaultClient) GetTokenSecret() *api.Secret {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.authSecret
}

// Close un-initializes this Client, stopping its LifetimeWatcher in the process and optionally revoking the token.
// It is safe to be called multiple times.
func (c *defaultClient) Close(revoke bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.inClosing = true
	logger := log.FromContext(nil).WithValues("id", c.id)
	logger.Info("Close() called")
	if c.watcher != nil {
		c.watcher.Stop()
	}

	if revoke && c.client != nil {
		if err := c.client.Auth().Token().RevokeSelf(""); err != nil {
			logger.V(consts.LogLevelWarning).Info(
				"Failed to revoke Vault client token", "err", err)
		}
	}
	c.id = ""
	c.closed = true
}

// startLifetimeWatcher starts an api.LifetimeWatcher in a Go routine for this Client.
// This will ensure that the auth token is periodically renewed.
// If the Client's token is not renewable an error will be returned.
func (c *defaultClient) startLifetimeWatcher(ctx context.Context) error {
	if c.skipRenewal {
		return nil
	}
	// try renewing the token as soon as possible, returning any renewal
	// failure before starting the lifetimeWatcher
	if err := c.renew(ctx); err != nil {
		return err
	}

	if !c.authSecret.Auth.Renewable {
		return fmt.Errorf("auth token is not renewable, cannot start the LifetimeWatcher")
	}

	if c.watcher != nil {
		return fmt.Errorf("lifetimeWatcher already started")
	}

	watcher, err := c.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: c.authSecret,
	})
	if err != nil {
		return err
	}

	cacheKey, _ := c.getCacheKey()
	watcherID := uuid.NewString()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(ctx context.Context, c *defaultClient, watcher *api.LifetimeWatcher) {
		logger := log.FromContext(nil).WithName("lifetimeWatcher").WithValues(
			"id", watcherID, "entityID", c.authSecret.Auth.EntityID,
			"clientID", c.id, "cacheKey", cacheKey)
		logger.Info("Starting")
		defer func() {
			logger.Info("Stopping")
			watcher.Stop()
		}()

		go watcher.Start()
		c.watcher = watcher
		wg.Done()
		logger.V(consts.LogLevelDebug).Info("Started")
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-watcher.DoneCh():
				if err != nil {
					logger.Error(err, "LifetimeWatcher completed with an error")
					c.lastWatcherErr = err
				}

				c.watcher = nil
				if c.watcherDoneCh != nil {
					if !c.inClosing {
						logger.V(consts.LogLevelTrace).Info("Writing to watcherDone channel")
						c.watcherDoneCh <- c
					} else {
						logger.V(consts.LogLevelTrace).Info("In closing, not writing to watcherDone channel")
					}
				} else {
					logger.V(consts.LogLevelTrace).Info("Skipping, watcherDone channel not set")
				}

				return
			case renewal := <-watcher.RenewCh():
				logger.V(consts.LogLevelDebug).Info("Successfully renewed the client")

				c.authSecret = renewal.Secret
				c.lastRenewal = renewal.RenewedAt.Unix()
			}
		}
	}(ctx, c, watcher)
	wg.Wait()

	return nil
}

// Login the Client to Vault. Upon success, if the auth token is renewable,
// an api.LifetimeWatcher will be started to ensure that the token is periodically renewed.
func (c *defaultClient) Login(ctx context.Context, client ctrlclient.Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client instance is closed")
	}

	var errs error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationLogin)
		c.incrementOperationCounter(metrics.OperationLogin, errs)
	}()
	if c.watcher != nil {
		c.watcher.Stop()
	}

	creds, err := c.credentialProvider.GetCreds(ctx, client)
	if err != nil {
		errs = err
		return errs
	}

	if len(c.authObj.Spec.Headers) > 0 {
		defer c.client.SetHeaders(c.client.Headers())
		headers := c.client.Headers()
		for k, v := range c.authObj.Spec.Headers {
			headers[k] = []string{v}
		}
		c.client.SetHeaders(headers)
	}

	path := fmt.Sprintf("auth/%s/login", c.authObj.Spec.Mount)
	resp, err := c.Write(ctx, &defaultWriteRequest{
		path:   path,
		params: creds,
	})
	if err != nil {
		errs = err
		return errs
	}

	c.client.SetToken(resp.Secret().Auth.ClientToken)

	c.authSecret = resp.Secret()
	c.lastRenewal = time.Now().Unix()

	id, err := c.hashAccessor()
	if err != nil {
		return err
	}

	c.id = id

	if resp.Secret().Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			errs = err
			return errs
		}
	}

	c.inClosing = false
	c.closed = false

	return nil
}

func (c *defaultClient) hashAccessor() (string, error) {
	accessor, err := c.accessor()
	if err != nil {
		return "", err
	}

	if accessor == "" {
		return "", nil
	}

	// obfuscate the accessor since it is considered sensitive information.
	return fmt.Sprintf("%x", blake2b.Sum256([]byte(accessor))), nil
}

func (c *defaultClient) accessor() (string, error) {
	if c.authSecret == nil {
		return "", nil
	}

	accessor, err := c.authSecret.TokenAccessor()
	if err != nil {
		return "", err
	}

	if accessor == "" {
		return "", nil
	}

	return accessor, nil
}

// ID returns the client's unique ID. If the client is not logged in, an empty
// string is returned. An empty ID should be considered invalid as it might
// indicate the client may not have ever successfully authenticated. The ID is a
// hash of the client token accessor which should at least be unique within a
// Vault cluster based on:
// https://github.com/hashicorp/vault/blob/f86e3d4a68c6329ee3229aa742fb969c099b2d12/vault/token_store.go#L994
func (c *defaultClient) ID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.id
}

func (c *defaultClient) GetVaultAuthObj() *secretsv1beta1.VaultAuth {
	return c.authObj
}

func (c *defaultClient) GetVaultConnectionObj() *secretsv1beta1.VaultConnection {
	return c.connObj
}

func (c *defaultClient) Read(ctx context.Context, request ReadRequest) (Response, error) {
	var err error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationRead)
		c.incrementOperationCounter(metrics.OperationRead, err)
	}()

	var respFunc func(*api.Secret) Response
	switch t := request.(type) {
	case *defaultReadRequest:
		respFunc = NewDefaultResponse
	case *kvReadRequestV1:
		respFunc = NewKVV1Response
	case *kvReadRequestV2:
		respFunc = NewKVV2Response
	default:
		return nil, fmt.Errorf("unsupported ReadRequest type %T", t)
	}

	path := request.Path()
	var secret *api.Secret
	secret, err = c.client.Logical().ReadWithDataWithContext(ctx, path, request.Values())
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("empty response from Vault, path=%q", path)
	}

	return respFunc(secret), nil
}

func (c *defaultClient) Write(ctx context.Context, req WriteRequest) (Response, error) {
	var err error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationWrite)
		c.incrementOperationCounter(metrics.OperationWrite, err)
	}()

	var secret *api.Secret
	secret, err = c.client.Logical().WriteWithContext(ctx, req.Path(), req.Params())

	return &defaultResponse{secret: secret}, err
}

func (c *defaultClient) renew(ctx context.Context) error {
	// should be called from a write locked method only
	var errs error
	startTS := time.Now()
	defer func() {
		c.incrementOperationCounter(metrics.OperationRenew, errs)
		if errs == nil {
			c.observeTime(startTS, metrics.OperationRenew)
		}
	}()

	if c.authSecret == nil {
		errs = fmt.Errorf("cannot renew client token, never logged in")
		return errs
	}

	if !c.authSecret.Auth.Renewable {
		errs = fmt.Errorf("cannot renew client token, non-renewable")
		return errs
	}

	resp, err := c.Write(ctx, NewWriteRequest("/auth/token/renew-self", nil))
	if err != nil {
		c.authSecret = nil
		c.lastRenewal = 0
		errs = err
		return err
	} else {
		c.authSecret = resp.Secret()
		c.lastRenewal = time.Now().UTC().Unix()
	}
	return nil
}

func (c *defaultClient) init(ctx context.Context, client ctrlclient.Client,
	authObj *secretsv1beta1.VaultAuth, connObj *secretsv1beta1.VaultConnection,
	providerNamespace string, opts *ClientOptions,
) error {
	if connObj == nil {
		return errors.New("VaultConnection was nil")
	}
	if authObj == nil {
		return errors.New("VaultAuth was nil")
	}

	cfg := &ClientConfig{
		Address:         connObj.Spec.Address,
		SkipTLSVerify:   connObj.Spec.SkipTLSVerify,
		TLSServerName:   connObj.Spec.TLSServerName,
		VaultNamespace:  authObj.Spec.Namespace,
		K8sNamespace:    connObj.Namespace,
		CACertSecretRef: connObj.Spec.CACertSecretRef,
		Headers:         connObj.Spec.Headers,
	}

	vc, err := MakeVaultClient(ctx, cfg, client)
	if err != nil {
		return err
	}

	credentialProvider, err := credentials.NewCredentialProvider(ctx, client, authObj, providerNamespace)
	if err != nil {
		return err
	}

	c.skipRenewal = opts.SkipRenewal
	c.credentialProvider = credentialProvider
	c.client = vc
	c.authObj = authObj
	c.connObj = connObj
	c.watcherDoneCh = opts.WatcherDoneCh

	return nil
}

func (c *defaultClient) observeTime(ts time.Time, operation string) {
	clientOperationTimes.WithLabelValues(operation, ctrlclient.ObjectKeyFromObject(c.connObj).String()).Observe(
		time.Since(ts).Seconds(),
	)
}

func (c *defaultClient) incrementOperationCounter(operation string, err error) {
	vaultConn := ctrlclient.ObjectKeyFromObject(c.connObj).String()
	clientOperations.WithLabelValues(operation, vaultConn).Inc()
	if err != nil {
		clientOperationErrors.WithLabelValues(operation, vaultConn).Inc()
	}
}

type MockRequest struct {
	Method string
	Path   string
	Params map[string]any
}

var _ ClientBase = (*MockRecordingVaultClient)(nil)

type MockRecordingVaultClient struct {
	Requests []*MockRequest
	Id       string
}

func (m *MockRecordingVaultClient) ID() string {
	return m.Id
}

func (m *MockRecordingVaultClient) Read(_ context.Context, s ReadRequest) (Response, error) {
	m.Requests = append(m.Requests, &MockRequest{
		Method: http.MethodGet,

		Path:   s.Path(),
		Params: nil,
	})

	return &defaultResponse{
		secret: &api.Secret{
			Data: make(map[string]interface{}),
		},
	}, nil
}

func (m *MockRecordingVaultClient) Write(_ context.Context, s WriteRequest) (Response, error) {
	m.Requests = append(m.Requests, &MockRequest{
		Method: http.MethodPut,
		Path:   s.Path(),
		Params: s.Params(),
	})
	return &defaultResponse{
		secret: &api.Secret{
			Data: make(map[string]interface{}),
		},
	}, nil
}
