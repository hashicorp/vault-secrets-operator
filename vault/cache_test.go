// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_clientCache_Prune(t *testing.T) {
	t.Parallel()

	dummyCallbackFunc := func(_ ClientCacheKey, _ Client) {}
	cacheSize := 10

	tests := []struct {
		name                  string
		filterFuncReturnsTrue bool
		cacheSize             int
		cacheLen              int
	}{
		{
			name:                  "cacheLen=1 and filterFunc returns true",
			filterFuncReturnsTrue: true,
			cacheLen:              1,
		},
		{
			name:                  "cacheLen=4 and filterFunc returns true",
			filterFuncReturnsTrue: true,
			cacheLen:              4,
		},
		{
			name:                  "cacheLen=1 and filterFunc returns false",
			filterFuncReturnsTrue: false,
			cacheLen:              1,
		},
		{
			name:                  "cacheLen=4 and filterFunc returns false",
			filterFuncReturnsTrue: false,
			cacheLen:              4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := lru.NewWithEvict[ClientCacheKey, Client](cacheSize, dummyCallbackFunc)
			require.NoError(t, err)
			cloneCache, err := lru.New[ClientCacheKey, Client](cacheSize)
			require.NoError(t, err)

			c := &clientCache{
				cache:      cache,
				cloneCache: cloneCache,
			}
			var expectedPrunedClients []Client
			for i := 0; i < tt.cacheLen; i++ {
				id := fmt.Sprintf("key%d", i)
				client := &defaultClient{
					id: id,
				}
				if tt.filterFuncReturnsTrue {
					expectedPrunedClients = append(expectedPrunedClients, client)
				}
				c.cache.Add(ClientCacheKey(id), client)
			}
			assert.Equal(t, tt.cacheLen, c.cache.Len(),
				"unexpected cache len before calling Prune()")
			actual := c.Prune(func(Client) bool {
				return tt.filterFuncReturnsTrue
			})
			assert.EqualValues(t, expectedPrunedClients, actual)
			assert.Equal(t, tt.cacheLen-len(expectedPrunedClients), c.cache.Len())
		})
	}
}
