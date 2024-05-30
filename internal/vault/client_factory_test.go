// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			ctxTimeout := time.Duration(tt.tryLockCount) * (holdLockDuration * 2)
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
