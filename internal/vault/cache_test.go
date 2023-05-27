// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	lru "github.com/hashicorp/golang-lru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_clientCache_Prune(t *testing.T) {
	dummyCallbackFunc := func(key, value interface{}) {}
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
			c := &clientCache{}
			cache, err := lru.NewWithEvict(cacheSize, dummyCallbackFunc)
			c.cache = cache
			require.NoError(t, err)

			var expectedPrunedKeys []ClientCacheKey
			for i := 0; i < tt.cacheLen; i++ {
				client := &defaultClient{
					// for simplicity, client is clone. pruneClones() should be tested separately
					isClone: true,
				}
				key := ClientCacheKey(fmt.Sprintf("key%d", i))
				if tt.filterFuncReturnsTrue {
					expectedPrunedKeys = append(expectedPrunedKeys, key)
				}
				c.cache.Add(key, client)
			}
			assert.Equal(t, tt.cacheLen, c.cache.Len(), "unexpected cache len before calling Prune()")
			keys := c.Prune(func(Client) bool {
				return tt.filterFuncReturnsTrue
			})
			assert.EqualValues(t, expectedPrunedKeys, keys)
			assert.Equal(t, tt.cacheLen-len(expectedPrunedKeys), c.cache.Len())
		})
	}
}
