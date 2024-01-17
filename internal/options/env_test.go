// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package options

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		envs        map[string]string
		wantOptions VSOEnvOptions
	}{
		"empty": {
			envs:        map[string]string{},
			wantOptions: VSOEnvOptions{},
		},
		"set all": {
			envs: map[string]string{
				"VSO_OUTPUT_FORMAT":                  "json",
				"VSO_CLIENT_CACHE_SIZE":              "100",
				"VSO_CLIENT_CACHE_PERSISTENCE_MODEL": "memory",
				"VSO_MAX_CONCURRENT_RECONCILES":      "10",
				"VSO_MAX_CONCURRENT_RECONCILES_VDS":  "20",
				"VSO_MIN_REFRESH_AFTER_HVSA":         "1h",
			},
			wantOptions: VSOEnvOptions{
				OutputFormat:                "json",
				ClientCacheSize:             makeInt(t, 100),
				ClientCachePersistenceModel: "memory",
				MaxConcurrentReconciles:     makeInt(t, 10),
				MaxConcurrentReconcilesVDS:  makeInt(t, 20),
				MinRefreshAfterHVSA:         1 * time.Hour,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				for env := range tt.envs {
					require.NoError(t, os.Unsetenv(env))
				}
			}()
			for env, val := range tt.envs {
				require.NoError(t, os.Setenv(env, val))
			}

			gotOptions := VSOEnvOptions{}
			require.NoError(t, gotOptions.Parse())
			assert.Equal(t, tt.wantOptions, gotOptions)
		})
	}
}

func makeInt(t *testing.T, i int) *int {
	t.Helper()
	return &i
}
