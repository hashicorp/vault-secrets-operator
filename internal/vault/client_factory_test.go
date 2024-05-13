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
