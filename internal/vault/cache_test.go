// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	lru "github.com/hashicorp/golang-lru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_clientCache_Prune(t *testing.T) {
	var (
		dummyCallbackFunc = func(key, value interface{}) {}
		size              = 256
		cacheLen          = 1
		err               error
		ctrl              = gomock.NewController(t)
	)

	tests := []struct {
		name                  string
		filterFuncReturnsTrue bool
		expectedCacheLen      int
	}{
		{
			name:                  "filterFunc returns true",
			filterFuncReturnsTrue: true,
			expectedCacheLen:      0,
		},
		{
			name:                  "filterFunc returns false",
			filterFuncReturnsTrue: false,
			expectedCacheLen:      cacheLen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &clientCache{}
			c.cache, err = lru.NewWithEvict(size, dummyCallbackFunc)
			require.NoError(t, err)

			for i := 0; i < cacheLen; i++ {
				mockClient := NewMockClient(ctrl)
				mockClient.EXPECT().Close().AnyTimes()
				if tt.filterFuncReturnsTrue {
					// for simplicity, client is not cloned. pruneClones() should be tested separately
					mockClient.EXPECT().IsClone().Return(false)
				}
				c.cache.Add(ClientCacheKey(fmt.Sprintf("key%d", i)), mockClient)
			}
			assert.Equal(t, cacheLen, c.cache.Len(), "unexpected cache len before calling Prune()")
			c.Prune(func(Client) bool {
				return tt.filterFuncReturnsTrue
			})
			assert.Equal(t, tt.expectedCacheLen, c.cache.Len())
		})
	}
}
