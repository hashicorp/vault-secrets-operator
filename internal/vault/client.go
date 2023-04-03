// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault/api"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

type ClientOptions struct {
	SkipRenewal bool
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
	var authObj *secretsv1alpha1.VaultAuth
	var providerNamespace string
	switch t := obj.(type) {
	case *secretsv1alpha1.VaultAuth:
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
		// otherwise we fall back to the common.GetVaultAuthAndTarget() to decide whether, or not obj is supported.
		a, target, err := common.GetVaultAuthAndTarget(ctx, client, obj)
		if err != nil {
			return nil, err
		}

		providerNamespace = target.Namespace
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

	if c.lastWatcherErr != nil {
		return nil, fmt.Errorf("restored client failed to be renewed, err=%w", err)
	}

	return c, nil
}

type Client interface {
	Init(context.Context, ctrlclient.Client, *secretsv1alpha1.VaultAuth, *secretsv1alpha1.VaultConnection, string, *ClientOptions) error
	Login(context.Context, ctrlclient.Client) error
	Read(context.Context, string) (*api.Secret, error)
	Restore(context.Context, *api.Secret) error
	Write(context.Context, string, map[string]any) (*api.Secret, error)
	Delete(context.Context, string) (*api.Secret, error)
	GetTokenSecret() *api.Secret
	CheckExpiry(int64) (bool, error)
	GetVaultAuthObj() *secretsv1alpha1.VaultAuth
	GetVaultConnectionObj() *secretsv1alpha1.VaultConnection
	GetCredentialProvider() CredentialProvider
	GetCacheKey() (ClientCacheKey, error)
	KVv1(string) (*api.KVv1, error)
	KVv2(string) (*api.KVv2, error)
	Close()
}

var _ Client = (*defaultClient)(nil)

type defaultClient struct {
	client             *api.Client
	authObj            *secretsv1alpha1.VaultAuth
	connObj            *secretsv1alpha1.VaultConnection
	authSecret         *api.Secret
	skipRenewal        bool
	lastRenewal        int64
	targetNamespace    string
	credentialProvider CredentialProvider
	watcher            *api.LifetimeWatcher
	lastWatcherErr     error
	once               sync.Once
	mu                 sync.RWMutex
}

func (c *defaultClient) GetCredentialProvider() CredentialProvider {
	return c.credentialProvider
}

func (c *defaultClient) KVv1(mount string) (*api.KVv1, error) {
	return c.client.KVv1(mount), nil
}

func (c *defaultClient) KVv2(mount string) (*api.KVv2, error) {
	return c.client.KVv2(mount), nil
}

func (c *defaultClient) GetCacheKey() (ClientCacheKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ComputeClientCacheKeyFromClient(c)
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

	if secret.Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (c *defaultClient) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth,
	connObj *secretsv1alpha1.VaultConnection, providerNamespace string, opts *ClientOptions,
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

// Close un-initializes this Client, stopping its LifetimeWatcher in the process.
// It is safe to be called multiple times.
func (c *defaultClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.FromContext(nil).Info("Calling Client.Close()")
	if c.watcher != nil {
		c.watcher.Stop()
	}
	c.client = nil
}

// startLifetimeWatcher starts an api.LifetimeWatcher in a Go routine for this Client.
// This will ensure that the auth token is periodically renewed.
// If the Client's token is not renewable an error will be returned.
func (c *defaultClient) startLifetimeWatcher(ctx context.Context) error {
	if c.skipRenewal {
		return nil
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

	go func(ctx context.Context, c *defaultClient, watcher *api.LifetimeWatcher) {
		logger := log.FromContext(nil).V(consts.LogLevelDebug).WithName("lifetimeWatcher").WithValues(
			"entityID", c.authSecret.Auth.EntityID)
		logger.Info("Starting")
		defer func() {
			logger.Info("Stopping")
			watcher.Stop()
			c.watcher = nil
		}()

		go watcher.Start()
		logger.Info("Started")
		c.watcher = watcher
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-watcher.DoneCh():
				if err != nil {
					logger.Error(err, "LifetimeWatcher completed with an error")
					c.lastWatcherErr = err
				}
				return
			case renewal := <-watcher.RenewCh():
				logger.Info("Successfully renewed the client")
				c.authSecret = renewal.Secret
				c.lastRenewal = renewal.RenewedAt.Unix()
			}
		}
	}(ctx, c, watcher)

	return nil
}

// Login the Client to Vault. Upon success, if the auth token is renewable,
// an api.LifetimeWatcher will be started to ensure that the token is periodically renewed.
func (c *defaultClient) Login(ctx context.Context, client ctrlclient.Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	resp, err := c.Write(ctx, path, creds)
	if err != nil {
		errs = err
		return errs
	}

	c.client.SetToken(resp.Auth.ClientToken)

	c.authSecret = resp
	c.lastRenewal = time.Now().Unix()

	if resp.Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			errs = err
			return errs
		}
	}

	return nil
}

func (c *defaultClient) GetVaultAuthObj() *secretsv1alpha1.VaultAuth {
	return c.authObj
}

func (c *defaultClient) GetVaultConnectionObj() *secretsv1alpha1.VaultConnection {
	return c.connObj
}

func (c *defaultClient) Read(ctx context.Context, path string) (*api.Secret, error) {
	var err error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationRead)
		c.incrementOperationCounter(metrics.OperationRead, err)
	}()

	var secret *api.Secret
	secret, err = c.client.Logical().ReadWithContext(ctx, path)
	return secret, err
}

func (c *defaultClient) Write(ctx context.Context, path string, m map[string]any) (*api.Secret, error) {
	var err error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationWrite)
		c.incrementOperationCounter(metrics.OperationWrite, err)
	}()

	var secret *api.Secret
	secret, err = c.client.Logical().WriteWithContext(ctx, path, m)
	return secret, err
}

func (c *defaultClient) Delete(ctx context.Context, path string) (*api.Secret, error) {
	var err error
	startTS := time.Now()
	defer func() {
		c.observeTime(startTS, metrics.OperationWrite)
		c.incrementOperationCounter(metrics.OperationWrite, err)
	}()

	var secret *api.Secret
	secret, err = c.client.Logical().DeleteWithContext(ctx, path)
	return secret, err
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

	resp, err := c.Write(ctx, "/auth/token/renew-self", nil)
	if err != nil {
		c.authSecret = nil
		c.lastRenewal = 0
		errs = err
		return err
	} else {
		c.authSecret = resp
		c.lastRenewal = time.Now().UTC().Unix()
	}
	return nil
}

func (c *defaultClient) init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, connObj *secretsv1alpha1.VaultConnection, providerNamespace string, opts *ClientOptions) error {
	cfg := &ClientConfig{
		Address:         connObj.Spec.Address,
		SkipTLSVerify:   connObj.Spec.SkipTLSVerify,
		TLSServerName:   connObj.Spec.TLSServerName,
		VaultNamespace:  authObj.Spec.Namespace,
		CACertSecretRef: connObj.Spec.CACertSecretRef,
		K8sNamespace:    providerNamespace,
	}

	vc, err := MakeVaultClient(ctx, cfg, client)
	if err != nil {
		return err
	}

	credentialProvider, err := NewCredentialProvider(ctx, client, authObj, providerNamespace)
	if err != nil {
		return err
	}

	c.skipRenewal = opts.SkipRenewal
	c.credentialProvider = credentialProvider
	c.client = vc
	c.authObj = authObj
	c.connObj = connObj

	return nil
}

func (c *defaultClient) observeTime(ts time.Time, operation string) {
	clientOperationTimes.WithLabelValues(operation, ctrlclient.ObjectKeyFromObject(c.connObj).String()).Observe(
		time.Since(ts).Seconds(),
	)
}

func (c *defaultClient) incrementOperationCounter(operation string, err error) {
	vaultConn := ctrlclient.ObjectKeyFromObject(c.connObj).String()
	clientOperationErrors.WithLabelValues(operation, vaultConn).Inc()
	if err != nil {
		clientOperations.WithLabelValues(operation, vaultConn).Inc()
	}
}
