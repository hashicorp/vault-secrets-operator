// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package options

import (
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
				"VSO_BACKOFF_INITIAL_INTERVAL":       "1s",
				"VSO_BACKOFF_MAX_INTERVAL":           "60s",
				"VSO_BACKOFF_MAX_ELAPSED_TIME":       "24h",
				"VSO_BACKOFF_RANDOMIZATION_FACTOR":   "0.5",
				"VSO_BACKOFF_MULTIPLIER":             "2.5",
			},
			wantOptions: VSOEnvOptions{
				OutputFormat:                "json",
				ClientCacheSize:             makeInt(t, 100),
				ClientCachePersistenceModel: "memory",
				MaxConcurrentReconciles:     makeInt(t, 10),
				BackoffInitialInterval:      time.Second * 1,
				BackoffMaxInterval:          time.Second * 60,
				BackoffMaxElapsedTime:       time.Hour * 24,
				BackoffRandomizationFactor:  0.5,
				BackoffMultiplier:           2.5,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for env, val := range tt.envs {
				t.Setenv(env, val)
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
