// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault/api"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// NewClient returns a Client specific to obj.
// Supported objects can be found in common.GetVaultAuthAndTarget.
// An error will be returned if obj is deemed to be invalid.
func NewClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	authObj, target, err := common.GetVaultAuthAndTarget(ctx, client, obj)
	if err != nil {
		return nil, err
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
	if err := c.Init(ctx, client, authObj, connObj, target.Namespace); err != nil {
		return nil, err
	}
	return c, nil
}

// NewClientWithLogin returns a logged-in Client specific to obj.
// Supported objects can be found in common.GetVaultAuthAndTarget.
// An error will be returned if obj is deemed to be invalid.
func NewClientWithLogin(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	c, err := NewClient(ctx, client, obj)
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
func NewClientFromStorageEntry(ctx context.Context, client ctrlclient.Client, entry *clientCacheStorageEntry) (Client, error) {
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
	if err := c.Init(ctx, client, authObj, connObj, entry.ProviderNamespace); err != nil {
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
	Init(context.Context, ctrlclient.Client, *secretsv1alpha1.VaultAuth, *secretsv1alpha1.VaultConnection, string) error
	Login(context.Context, ctrlclient.Client) error
	Read(context.Context, string) (*api.Secret, error)
	Restore(context.Context, *api.Secret) error
	Write(context.Context, string, map[string]any) (*api.Secret, error)
	GetTokenSecret() (*api.Secret, error)
	CheckExpiry(int64) (bool, error)
	GetVaultAuthObj() (*secretsv1alpha1.VaultAuth, error)
	GetVaultConnectionObj() (*secretsv1alpha1.VaultConnection, error)
	GetCredentialProvider() (CredentialProvider, error)
	GetCacheKey() (ClientCacheKey, error)
	KVv1(string) (*api.KVv1, error)
	KVv2(string) (*api.KVv2, error)
	Close()
}

var _ Client = (*defaultClient)(nil)

type defaultClient struct {
	initialized        bool
	client             *api.Client
	authObj            *secretsv1alpha1.VaultAuth
	connObj            *secretsv1alpha1.VaultConnection
	lastResp           *api.Secret
	lastRenewal        int64
	targetNamespace    string
	credentialProvider CredentialProvider
	watcher            *api.LifetimeWatcher
	lastWatcherErr     error
	once               sync.Once
	mu                 sync.RWMutex
}

func (c *defaultClient) GetCredentialProvider() (CredentialProvider, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	return c.credentialProvider, nil
}

func (c *defaultClient) KVv1(mount string) (*api.KVv1, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	return c.client.KVv1(mount), nil
}

func (c *defaultClient) KVv2(mount string) (*api.KVv2, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	return c.client.KVv2(mount), nil
}

func (c *defaultClient) GetCacheKey() (ClientCacheKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if err := c.checkInitialized(); err != nil {
		return "", err
	}

	return ComputeClientCacheKeyFromClient(c)
}

// Restore self from the provided api.Secret (should have an Auth configured).
// The provided Client Token will be renewed as well.
func (c *defaultClient) Restore(ctx context.Context, secret *api.Secret) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return fmt.Errorf("not initialized")
	}

	if c.watcher != nil {
		c.watcher.Stop()
	}

	if secret == nil {
		return fmt.Errorf("api.Secret is nil")
	}

	if secret.Auth == nil {
		return fmt.Errorf("not an auth secret")
	}

	c.lastResp = secret
	c.client.SetToken(secret.Auth.ClientToken)

	if secret.Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (c *defaultClient) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, connObj *secretsv1alpha1.VaultConnection, providerNamespace string) error {
	if c.initialized {
		return fmt.Errorf("aleady initialized")
	}

	var err error
	c.once.Do(func() {
		err = c.init(ctx, client, authObj, connObj, providerNamespace)
		if err == nil {
			c.initialized = true
		}
	})

	return err
}

func (c *defaultClient) getTokenTTL() (time.Duration, error) {
	return c.lastResp.TokenTTL()
}

func (c *defaultClient) CheckExpiry(offset int64) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.initialized {
		return false, fmt.Errorf("not initialized")
	}

	if c.lastResp == nil || c.lastRenewal == 0 {
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

func (c *defaultClient) GetTokenSecret() (*api.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.initialized {
		return nil, fmt.Errorf("not initialized")
	}

	return c.lastResp, nil
}

// Close un-initializes this Client, stopping its LifetimeWatcher in the process.
// It is safe to be called multiple times.
func (c *defaultClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return
	}

	log.FromContext(nil).Info("Calling Client.Close()")
	if c.watcher != nil {
		c.watcher.Stop()
	}
	c.client = nil
	c.initialized = false
}

// startLifetimeWatcher starts an api.LifetimeWatcher in a Go routine for this Client.
// This will ensure that the auth token is periodically renewed.
// If the Client's token is not renewable an error will be returned.
func (c *defaultClient) startLifetimeWatcher(ctx context.Context) error {
	if err := c.checkInitialized(); err != nil {
		return err
	}

	if !c.lastResp.Auth.Renewable {
		return fmt.Errorf("auth token is not renewable, cannot start the LifetimeWatcher")
	}

	if c.watcher != nil {
		return fmt.Errorf("lifetimeWatcher already started")
	}

	watcher, err := c.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
		Secret: c.lastResp,
	})
	if err != nil {
		return err
	}

	go func(ctx context.Context, c *defaultClient, watcher *api.LifetimeWatcher) {
		logger := log.FromContext(ctx).WithName("LifetimeWatcher").WithValues(
			"entityID", c.lastResp.Auth.EntityID)
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
				c.lastResp = renewal.Secret
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
	if err := c.checkInitialized(); err != nil {
		return err
	}
	// TODO: add logging, preferably with a Logger that supports more levels than just INFO and ERROR.

	if c.watcher != nil {
		c.watcher.Stop()
	}

	creds, err := c.credentialProvider.GetCreds(ctx, client)
	if err != nil {
		return err
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
		return err
	}

	c.client.SetToken(resp.Auth.ClientToken)

	c.lastResp = resp
	c.lastRenewal = time.Now().Unix()

	if resp.Auth.Renewable {
		if err := c.startLifetimeWatcher(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (c *defaultClient) GetVaultAuthObj() (*secretsv1alpha1.VaultAuth, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	return c.authObj, nil
}

func (c *defaultClient) GetVaultConnectionObj() (*secretsv1alpha1.VaultConnection, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	return c.connObj, nil
}

func (c *defaultClient) Read(ctx context.Context, path string) (*api.Secret, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	// TODO: add metrics
	return c.client.Logical().ReadWithContext(ctx, path)
}

func (c *defaultClient) Write(ctx context.Context, path string, m map[string]any) (*api.Secret, error) {
	if err := c.checkInitialized(); err != nil {
		return nil, err
	}

	// TODO: add metrics
	return c.client.Logical().WriteWithContext(ctx, path, m)
}

func (c *defaultClient) checkInitialized() error {
	if !c.initialized {
		return fmt.Errorf("not initialized")
	}
	return nil
}

func (c *defaultClient) renew(ctx context.Context) error {
	// should be called from a write locked method only
	if c.lastResp == nil {
		return fmt.Errorf("cannot renew client token, never logged in")
	}

	if !c.lastResp.Auth.Renewable {
		return fmt.Errorf("cannot renew client token, non-renewable")
	}

	resp, err := c.Write(ctx, "/auth/token/renew-self", nil)
	if err != nil {
		c.lastResp = nil
		c.lastRenewal = 0
		return err
	} else {
		c.lastResp = resp
		c.lastRenewal = time.Now().UTC().Unix()
	}
	return nil
}

func (c *defaultClient) init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, connObj *secretsv1alpha1.VaultConnection, providerNamespace string) error {
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

	c.credentialProvider = credentialProvider
	c.client = vc
	c.authObj = authObj
	c.connObj = connObj

	return nil
}
