// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/credentials"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	vconsts "github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
)

func Test_cachingClientFactory_RegisterClientCallbackHandler(t *testing.T) {
	cb1 := func(_ context.Context, _ Client) {
		// do nothing
	}
	cb2 := func(_ context.Context, _ Client) {
		// do nothing
	}
	cb3 := func(_ context.Context, _ Client) {
		// do nothing
	}
	tests := []struct {
		name    string
		cbs     []ClientCallbackHandler
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "single",
			cbs: []ClientCallbackHandler{
				{
					On:       ClientCallbackOnLifetimeWatcherDone,
					Callback: cb1,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "multiple",
			cbs: []ClientCallbackHandler{
				{
					On:       ClientCallbackOnLifetimeWatcherDone,
					Callback: cb1,
				},
				{
					On:       ClientCallbackOnLifetimeWatcherDone,
					Callback: cb2,
				},
				{
					On:       ClientCallbackOnLifetimeWatcherDone,
					Callback: cb3,
				},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &cachingClientFactory{}
			require.Greater(t, len(tt.cbs), 0, "no test ClientCallbackHandlers provided")

			wg := sync.WaitGroup{}
			wg.Add(len(tt.cbs))
			for _, cb := range tt.cbs {
				go func(cb ClientCallbackHandler) {
					defer wg.Done()
					m.RegisterClientCallbackHandler(cb)
				}(cb)
			}
			wg.Wait()
			assert.Equal(t, len(tt.cbs), len(m.clientCallbacks))
		})
	}
}

func Test_cachingClientFactory_clientLocks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cacheKey     ClientCacheKey
		tryLockCount int
		wantInLocks  bool
		clientLocks  map[ClientCacheKey]*sync.RWMutex
	}{
		{
			name:         "single-new",
			cacheKey:     ClientCacheKey("single"),
			tryLockCount: 1,
			wantInLocks:  false,
		},
		{
			name:     "single-existing",
			cacheKey: ClientCacheKey("single-existing"),
			clientLocks: map[ClientCacheKey]*sync.RWMutex{
				ClientCacheKey("single-existing"): {},
			},
			tryLockCount: 1,
			wantInLocks:  true,
		},
		{
			name:         "concurrent-new",
			cacheKey:     ClientCacheKey("concurrent-new"),
			tryLockCount: 10,
			wantInLocks:  false,
		},
		{
			name:     "concurrent-existing",
			cacheKey: ClientCacheKey("concurrent-existing"),
			clientLocks: map[ClientCacheKey]*sync.RWMutex{
				ClientCacheKey("concurrent-existing"): {},
			},
			tryLockCount: 10,
			wantInLocks:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Greater(t, tt.tryLockCount, 0, "no test tryLockCount provided")

			if tt.clientLocks == nil {
				tt.clientLocks = make(map[ClientCacheKey]*sync.RWMutex)
			}

			m := &cachingClientFactory{
				clientLocks: tt.clientLocks,
			}

			got, inLocks := m.clientLock(tt.cacheKey)
			if !tt.wantInLocks {
				assert.Equal(t, got, tt.clientLocks[tt.cacheKey])
			}
			require.Equal(t, tt.wantInLocks, inLocks)

			// holdLockDuration is the duration each locker will hold the lock for after it
			// is acquired.
			holdLockDuration := 2 * time.Millisecond
			// ctxTimeout is the total time to wait for all lockers to acquire the lock once.
			ctxTimeout := time.Duration(tt.tryLockCount) * (holdLockDuration * 10)
			ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
			go func() {
				defer cancel()
				time.Sleep(ctxTimeout)
			}()

			wg := sync.WaitGroup{}
			wg.Add(tt.tryLockCount)
			for i := 0; i < tt.tryLockCount; i++ {
				go func(ctx context.Context) {
					defer wg.Done()
					lck, _ := m.clientLock(tt.cacheKey)
					lck.Lock()
					defer lck.Unlock()
					assert.Equal(t, got, lck)

					lockTimer := time.NewTimer(holdLockDuration)
					defer lockTimer.Stop()
					select {
					case <-lockTimer.C:
						return
					case <-ctx.Done():
						assert.NoError(t, ctx.Err(), "timeout waiting for lock")
						return
					}
				}(ctx)
			}
			wg.Wait()

			assert.NoError(t, ctx.Err(),
				"context timeout waiting for all lockers")
		})
	}
}

func Test_cachingClientFactory_callClientCallbacks(t *testing.T) {
	ctx := context.Background()
	type callbackResult struct {
		called bool
		done   bool
	}
	tests := []struct {
		name       string
		c          Client
		onMask     ClientCallbackOn
		cbOn       ClientCallbackOn
		cbFn       func(t *testing.T) (ClientCallback, *callbackResult)
		wait       bool
		wantCalled bool
	}{
		{
			name:   "single-on-lifetime-watcher-done",
			c:      &defaultClient{},
			onMask: ClientCallbackOnLifetimeWatcherDone,
			cbOn:   ClientCallbackOnLifetimeWatcherDone,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					result.called = true
					result.done = true
				}, result
			},
			wantCalled: true,
		},
		{
			name:   "single-on-cache-removal",
			c:      &defaultClient{},
			onMask: ClientCallbackOnCacheRemoval,
			cbOn:   ClientCallbackOnCacheRemoval,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					result.called = true
					result.done = true
				}, result
			},
			wantCalled: true,
		},
		{
			name:   "multi-on-lifetime-watcher-done",
			c:      &defaultClient{},
			onMask: ClientCallbackOnCacheRemoval | ClientCallbackOnLifetimeWatcherDone,
			cbOn:   ClientCallbackOnLifetimeWatcherDone,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					result.called = true
					result.done = true
				}, result
			},
			wantCalled: true,
		},
		{
			name:   "multi-on-cache-removal",
			c:      &defaultClient{},
			onMask: ClientCallbackOnCacheRemoval | ClientCallbackOnLifetimeWatcherDone,
			cbOn:   ClientCallbackOnCacheRemoval,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					result.called = true
					result.done = true
				}, result
			},
			wantCalled: true,
		},
		{
			name:   "single-not-called",
			c:      &defaultClient{},
			onMask: ClientCallbackOnLifetimeWatcherDone,
			cbOn:   ClientCallbackOnCacheRemoval,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					// should not be called
				}, result
			},
			wait:       true,
			wantCalled: false,
		},
		{
			name:   "single-not-called-unknown",
			c:      &defaultClient{},
			onMask: ClientCallbackOn(uint32(1024)),
			cbOn:   ClientCallbackOnCacheRemoval,
			cbFn: func(t *testing.T) (ClientCallback, *callbackResult) {
				result := &callbackResult{}
				return func(ctx context.Context, c Client) {
					// should not be called
				}, result
			},
			wait:       true,
			wantCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &cachingClientFactory{}
			cbFn, result := tt.cbFn(t)
			cb := ClientCallbackHandler{
				On:       tt.cbOn,
				Callback: cbFn,
			}

			m.RegisterClientCallbackHandler(cb)
			m.callClientCallbacks(ctx, tt.c, tt.onMask, tt.wait)
			if tt.wait {
				assert.Equal(t, tt.wantCalled, result.called)
			} else {
				assert.Eventually(t, func() bool {
					if result.done {
						assert.Equal(t, tt.wantCalled, result.called)
						return true
					}
					return false
				}, time.Second*1, time.Millisecond*100)
			}
		})
	}
}

type storageEncryptionClientTest struct {
	name               string
	client             ctrlclient.Client
	setupTimeout       time.Duration
	wantErr            assert.ErrorAssertionFunc
	connObj            *secretsv1beta1.VaultConnection
	authObj            *secretsv1beta1.VaultAuth
	saObj              *corev1.ServiceAccount
	testHandler        *testHandler
	factoryFunc        credentials.CredentialProviderFactoryFunc
	testScenario       int
	callCount          int
	expectRequestCount int
}

func Test_cachingClientFactory_storageEncryptionClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	builder := testutils.NewFakeClientBuilder()
	vcObj := &secretsv1beta1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: common.OperatorNamespace,
			Labels: map[string]string{
				"cacheStorageEncryption": "true",
			},
			UID: connUID,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Timeout: "10s",
		},
	}

	vcObjTimeout5s := vcObj.DeepCopy()
	vcObjTimeout5s.Spec.Timeout = "5s"

	saObj := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: common.OperatorNamespace,
			UID:       providerUID,
		},
	}

	vaObj := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: common.OperatorNamespace,
			Labels: map[string]string{
				"cacheStorageEncryption": "true",
			},
			UID: authUID,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: vconsts.ProviderMethodKubernetes,
			Mount:  "baz",
			StorageEncryption: &secretsv1beta1.StorageEncryption{
				Mount:   "foo",
				KeyName: "baz",
			},
		},
	}

	authHandlerFunc := func(t *testHandler, w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			s := &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 100,
					Accessor:      fmt.Sprintf("foo-%d", t.requestCount),
				},
			}
			b, err := json.Marshal(s)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, err = w.Write(b)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	authHandlerBlockingFunc := func(t *testHandler, w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			time.Sleep(time.Second * 30)
			w.WriteHeader(http.StatusRequestTimeout)
			return
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	factoryFunc := func(ctx context.Context, c ctrlclient.Client, obj ctrlclient.Object, s string) (provider.CredentialProviderBase, error) {
		switch authObj := obj.(type) {
		case *secretsv1beta1.VaultAuth:
			switch authObj.Spec.Method {
			case vconsts.ProviderMethodKubernetes:
				p := credentials.NewFakeCredentialProvider().WithUID(saObj.GetUID())
				if err := p.Init(ctx, c, authObj, s); err != nil {
					return nil, err
				}
				return p, nil
			default:
				return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
			}
		}
		return nil, fmt.Errorf("unsupported auth object %T", obj)
	}

	tests := []storageEncryptionClientTest{
		{
			name:    "nil-client",
			wantErr: assert.Error,
		},
		{
			name:         "concurrency",
			client:       builder.Build(),
			connObj:      vcObj.DeepCopy(),
			saObj:        saObj.DeepCopy(),
			authObj:      vaObj.DeepCopy(),
			testScenario: 1,
			factoryFunc:  factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerFunc,
			},
			callCount:          30,
			expectRequestCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:         "concurrency-blocking",
			client:       builder.Build(),
			connObj:      vcObj.DeepCopy(),
			saObj:        saObj.DeepCopy(),
			authObj:      vaObj.DeepCopy(),
			testScenario: 1,
			factoryFunc:  factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerFunc,
			},
			callCount:          30,
			expectRequestCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:         "concurrency-invalid-client",
			client:       builder.Build(),
			connObj:      vcObj.DeepCopy(),
			saObj:        saObj.DeepCopy(),
			authObj:      vaObj.DeepCopy(),
			testScenario: 2,
			factoryFunc:  factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerFunc,
			},
			callCount:          30,
			expectRequestCount: 31,
			wantErr:            assert.NoError,
		},
		{
			name:         "full-lifecycle",
			client:       builder.Build(),
			connObj:      vcObj.DeepCopy(),
			saObj:        saObj.DeepCopy(),
			authObj:      vaObj.DeepCopy(),
			testScenario: 3,
			factoryFunc:  factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerFunc,
			},
			expectRequestCount: 3,
			wantErr:            assert.NoError,
		},
		{
			name:        "vault-client-request-timeout",
			client:      builder.Build(),
			connObj:     vcObjTimeout5s.DeepCopy(),
			saObj:       saObj.DeepCopy(),
			authObj:     vaObj.DeepCopy(),
			factoryFunc: factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerBlockingFunc,
			},
			expectRequestCount: 1,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.ErrorIs(t, err, context.DeadlineExceeded, i...) {
					return assert.ErrorContains(t, err, "failed to setup encryption client")
				}
				return false
			},
		},
		{
			name:        "vault-client-setup-timeout",
			client:      builder.Build(),
			connObj:     vcObj.DeepCopy(),
			saObj:       saObj.DeepCopy(),
			authObj:     vaObj.DeepCopy(),
			factoryFunc: factoryFunc,
			testHandler: &testHandler{
				handlerFunc: authHandlerBlockingFunc,
			},
			expectRequestCount: 1,
			setupTimeout:       time.Second * 1,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.ErrorIs(t, err, context.DeadlineExceeded, i...) {
					return assert.ErrorContains(t, err, "setup timed out after")
				}
				return false
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCache, err := NewClientCache(5, nil, nil)
			require.NoError(t, err)

			if tt.testHandler != nil {
				config, l := NewTestHTTPServer(t, tt.testHandler.handler())
				t.Cleanup(func() {
					assert.NoError(t, l.Close())
				})

				if tt.connObj != nil {
					tt.connObj.Spec.Address = config.Address
				}
			}

			if tt.saObj != nil {
				err := tt.client.Create(ctx, tt.saObj)
				require.NoError(t, err)
			}

			if tt.connObj != nil {
				err := tt.client.Create(ctx, tt.connObj)
				require.NoError(t, err)
			}

			if tt.authObj != nil {
				err := tt.client.Create(ctx, tt.authObj)
				require.NoError(t, err)
			}

			m := &cachingClientFactory{
				credentialProviderFactory: credentials.NewFakeCredentialProviderFactory(tt.factoryFunc),
				cache:                     clientCache,
				encClientSetupTimeout:     tt.setupTimeout,
			}

			got0, err := m.storageEncryptionClient(ctx, tt.client)
			if !tt.wantErr(t, err, fmt.Sprintf("storageEncryptionClient(%v, %v)", ctx, tt.client)) {
				return
			}
			if err != nil {
				assert.Nil(t, got0)
				return
			}

			switch tt.testScenario {
			case 1, 2:
				require.GreaterOrEqual(t, tt.callCount, 10, "not enough calls for test scenario")
				ctx_, cancel := context.WithTimeout(ctx, time.Second*30)
				go func() {
					defer cancel()
					time.Sleep(time.Second * 30)
				}()

				doneCh := make(chan Client)
				t.Cleanup(func() {
					close(doneCh)
				})

				if tt.testScenario == 2 {
					invalidateClient(t, got0)
				}

				for i := 0; i < tt.callCount; i++ {
					go func() {
						g, err := m.storageEncryptionClient(ctx, tt.client)
						defer func() {
							doneCh <- g
						}()
						require.NoError(t, err)
						if tt.testScenario == 2 {
							// invalidate the client by setting LeaseDuration to 0, this tests that there
							// are no deadlocks
							invalidateClient(t, g)
						} else {
							assert.Equalf(t, got0, g, "unexpected client")
						}
						assertStorageEncryptionClient(t, tt, g)
					}()
				}

				var actualCallCount int
				for i := 0; i < tt.callCount; i++ {
					select {
					case <-ctx_.Done():
						assert.Fail(t, "timeout waiting for client creation")
						break
					case <-doneCh:
						actualCallCount++
					}
				}
				assert.Equalf(t, tt.callCount, actualCallCount, "unexpected number of function calls")
				assert.Equalf(t, tt.expectRequestCount, tt.testHandler.requestCount, "unexpected number of requests")
			case 3:
				// full lifecycle test
				cacheKey, err := got0.GetCacheKey()
				require.NoError(t, err)

				assertStorageEncryptionClient(t, tt, got0)
				assert.Equalf(t, 1, m.cache.Len(), "unexpected cache length")
				cachedClient, ok := m.cache.Get(cacheKey)
				if assert.Truef(t, ok, "expected client to be cached, cacheKey=%v", cacheKey) {
					assert.Equalf(t, got0, cachedClient, "unexpected cached client")
				}

				// get the client again to test cache hit
				require.Equalf(t, m.clientCacheKeyEncrypt, cacheKey, "unexpected cache key")
				got1, err := m.storageEncryptionClient(ctx, tt.client)
				require.NoError(t, err)
				require.Equalf(t, got1, cachedClient, "unexpected cached client")
				require.Equalf(t, m.clientCacheKeyEncrypt, cacheKey, "unexpected cache key")
				assert.Equalf(t, 1, tt.testHandler.requestCount, "unexpected request count")
				assertStorageEncryptionClient(t, tt, got1)

				invalidateClient(t, got1)
				got2, err := m.storageEncryptionClient(ctx, tt.client)
				require.NoError(t, err)
				require.NotEqualf(t, got2, cachedClient, "unexpected cached client")
				assertStorageEncryptionClient(t, tt, got2)

				// Update the auth object to trigger a new client cache key is set on the next call
				tt.authObj.Generation++
				require.NoError(t, tt.client.Update(ctx, tt.authObj))
				// remove the cached client to trigger a new client creation
				m.cache.Remove(cacheKey)
				got3, err := m.storageEncryptionClient(ctx, tt.client)
				require.NoError(t, err)
				assert.NotEqual(t, cacheKey, m.clientCacheKeyEncrypt, "expected new cache key")
				assert.Equalf(t, 1, m.cache.Len(), "unexpected cache length")
				assert.NotEqual(t, got2, got3)
				assertStorageEncryptionClient(t, tt, got3)

				// unset the storage encryption to trigger an error
				// remove the cached client to trigger a new client creation
				tt.authObj.Spec.StorageEncryption = nil
				require.NoError(t, tt.client.Update(ctx, tt.authObj))
				// Set LeaseDuration to 0 to force handling of an invalid Client
				invalidateClient(t, got3)
				got4, err := m.storageEncryptionClient(ctx, tt.client)
				require.Error(t, err)
				assert.Nil(t, got4)
				assert.Equalf(t, 0, m.cache.Len(), "unexpected cache length")
				assert.Equalf(t, ClientCacheKey(""), m.clientCacheKeyEncrypt, "unexpected cache key")

				assert.Equalf(t, tt.expectRequestCount, tt.testHandler.requestCount, "unexpected request count")
			default:
				require.Fail(t, "unknown test scenario %d", tt.testScenario)
			}
		})
	}
}

func assertStorageEncryptionClient(t *testing.T, tt storageEncryptionClientTest, got Client) {
	t.Helper()

	assert.Equalf(t, tt.connObj, got.GetVaultConnectionObj(), "unexpected vault connection object")
	assert.Equalf(t, tt.authObj, got.GetVaultAuthObj(), "unexpected vault auth object")
	assert.Equalf(t, tt.saObj.UID, got.GetCredentialProvider().GetUID(), "unexpected credential provider UID")
}

func invalidateClient(t *testing.T, client Client) {
	t.Helper()

	secret := client.GetTokenSecret()
	require.NotNil(t, secret)
	secret.Auth.LeaseDuration = 0
}
