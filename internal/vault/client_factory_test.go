// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
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

func Test_cachingClientFactory_pruneOrphanClients(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	type keyTest struct {
		key                ClientCacheKey
		creationTimeOffset time.Duration
	}

	newCache := func(size int, keyTests ...keyTest) *clientCache {
		lruCache, err := lru.NewWithEvict[ClientCacheKey, Client](size, nil)
		require.NoError(t, err)
		c := &clientCache{
			cache: lruCache,
		}
		for _, k := range keyTests {
			c.cache.Add(k.key, &stubClient{
				cacheKey: k.key,
				clientStat: &ClientStat{
					createTime: time.Now().Add(k.creationTimeOffset),
				},
			})
		}
		return c
	}

	clientBuilder := newClientBuilder()
	schemeLessBuilder := fake.NewClientBuilder()
	tests := []struct {
		name                string
		cache               ClientCache
		c                   ctrlclient.Client
		want                int
		createFunc          func(t *testing.T, c ctrlclient.Client) error
		wantClientCacheKeys []ClientCacheKey
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:    "empty-cache",
			c:       clientBuilder.Build(),
			cache:   newCache(1),
			wantErr: assert.NoError,
		},
		{
			name: "no-referring-objects-purge",
			c:    clientBuilder.Build(),
			cache: newCache(1,
				keyTest{
					key:                "kubernetes-123456",
					creationTimeOffset: -defaultPruneOrphanAge,
				},
			),
			want:    1,
			wantErr: assert.NoError,
		},
		{
			name: "prune-some",
			c:    clientBuilder.Build(),
			createFunc: func(t *testing.T, c ctrlclient.Client) error {
				t.Helper()
				var errs error
				for _, o := range []ctrlclient.Object{
					&secretsv1beta1.VaultStaticSecret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "vss-1",
							Namespace: "default",
						},
						Status: secretsv1beta1.VaultStaticSecretStatus{
							VaultClientMeta: secretsv1beta1.VaultClientMeta{
								CacheKey: "kubernetes-123456",
							},
						},
					},
				} {
					errs = errors.Join(errs, c.Create(ctx, o))
				}
				return errs
			},
			cache: newCache(2,
				keyTest{
					key:                "kubernetes-123455",
					creationTimeOffset: -defaultPruneOrphanAge,
				},
				keyTest{
					key:                "kubernetes-123456",
					creationTimeOffset: -defaultPruneOrphanAge,
				},
			),
			wantClientCacheKeys: []ClientCacheKey{
				ClientCacheKey("kubernetes-123456"),
			},
			want:    1,
			wantErr: assert.NoError,
		},
		{
			name: "none",
			c:    clientBuilder.Build(),
			cache: newCache(1,
				keyTest{
					key:                "kubernetes-123456",
					creationTimeOffset: -defaultPruneOrphanAge,
				},
			),
			createFunc: func(t *testing.T, c ctrlclient.Client) error {
				t.Helper()
				var errs error
				for _, o := range []ctrlclient.Object{
					&secretsv1beta1.VaultStaticSecret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "vss-1",
							Namespace: "default",
						},
						Status: secretsv1beta1.VaultStaticSecretStatus{
							VaultClientMeta: secretsv1beta1.VaultClientMeta{
								CacheKey: "kubernetes-123456",
							},
						},
					},
					&secretsv1beta1.VaultPKISecret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "vps-1",
							Namespace: "default",
						},
						Status: secretsv1beta1.VaultPKISecretStatus{
							VaultClientMeta: secretsv1beta1.VaultClientMeta{
								CacheKey: "kubernetes-123456",
							},
						},
					},
					&secretsv1beta1.VaultDynamicSecret{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "vds-1",
							Namespace: "default",
						},
						Status: secretsv1beta1.VaultDynamicSecretStatus{
							VaultClientMeta: secretsv1beta1.VaultClientMeta{
								CacheKey: "kubernetes-123456",
							},
						},
					},
				} {
					errs = errors.Join(errs, c.Create(ctx, o))
				}
				return errs
			},
			wantErr: assert.NoError,
			wantClientCacheKeys: []ClientCacheKey{
				ClientCacheKey("kubernetes-123456"),
			},
			want: 0,
		},
		{
			name: "no-prune-recent",
			c:    clientBuilder.Build(),
			cache: newCache(2,
				keyTest{
					key:                "kubernetes-123455",
					creationTimeOffset: -(defaultPruneOrphanAge - time.Second*1),
				},
				keyTest{
					key:                "kubernetes-123456",
					creationTimeOffset: -(defaultPruneOrphanAge - time.Second*1),
				},
			),
			wantClientCacheKeys: []ClientCacheKey{
				ClientCacheKey("kubernetes-123455"),
				ClientCacheKey("kubernetes-123456"),
			},
			want:    0,
			wantErr: assert.NoError,
		},
		{
			name: "vss-scheme-not-set",
			c:    schemeLessBuilder.Build(),
			cache: newCache(1,
				keyTest{
					key:                "kubernetes-123456",
					creationTimeOffset: -defaultPruneOrphanAge,
				},
			),
			want: 0,
			wantClientCacheKeys: []ClientCacheKey{
				ClientCacheKey("kubernetes-123456"),
			},
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.ErrorContains(t, err, "no kind is registered for the type v1beta1.VaultStaticSecret")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &cachingClientFactory{
				cache:      tt.cache,
				ctrlClient: tt.c,
			}

			if tt.createFunc != nil {
				require.NoError(t, tt.createFunc(t, tt.c))
			}

			got, err := m.pruneOrphanClients(ctx)
			if !tt.wantErr(t, err, fmt.Sprintf("pruneOrphanClients(%v)", ctx)) {
				return
			}
			assert.Equalf(t, tt.want, got, "pruneOrphanClients(%v)", ctx)
			assert.ElementsMatchf(t, tt.wantClientCacheKeys, m.cache.Keys(), "pruneOrphanClients(%v)", ctx)
		})
	}
}

// newClientBuilder returns a new fake.ClientBuilder with the necessary schemes.
// copied from helpers
func newClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}

var _ Client = (*stubClient)(nil)

type stubClient struct {
	Client
	cacheKey           ClientCacheKey
	credentialProvider provider.CredentialProviderBase
	isClone            bool
	clientStat         *ClientStat
}

func (c *stubClient) GetCacheKey() (ClientCacheKey, error) {
	return c.cacheKey, nil
}

func (c *stubClient) IsClone() bool {
	return c.isClone
}

func (c *stubClient) Stat() *ClientStat {
	return c.clientStat
}
