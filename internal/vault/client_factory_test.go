// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"sync"
	"testing"

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
