// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package options

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// VSOEnvOptions are the supported environment variable options, prefixed with VSO.
// The names of the variables in the struct are split using camel case:
// Specification.ClientCacheSize = VSO_CLIENT_CACHE_SIZE
type VSOEnvOptions struct {
	// OutputFormat is the VSO_OUTPUT_FORMAT environment variable option
	OutputFormat string `split_words:"true"`

	// ClientCacheSize is the VSO_CLIENT_CACHE_SIZE environment variable option
	ClientCacheSize *int `split_words:"true"`

	// ClientCachePersistenceModel is the VSO_CLIENT_CACHE_PERSISTENCE_MODEL
	// environment variable option
	ClientCachePersistenceModel string `split_words:"true"`

	// MaxConcurrentReconciles is the VSO_MAX_CONCURRENT_RECONCILES environment variable option
	MaxConcurrentReconciles *int `split_words:"true"`

	// GlobalTransformationOptions is VSO_GLOBAL_TRANSFORMATION_OPTIONS environment variable option
	GlobalTransformationOptions string `split_words:"true"`

	// BackoffInitialInterval is VSO_BACKOFF_INITIAL_INTERVAL environment variable option
	BackoffInitialInterval time.Duration `split_words:"true"`

	// BackoffMaxInterval is VSO_BACKOFF_MAX_INTERVAL environment variable option
	BackoffMaxInterval time.Duration `split_words:"true"`

	// BackoffMaxElapsedTime is VSO_BACKOFF_MAX_ELAPSED_TIME environment variable option
	BackoffMaxElapsedTime time.Duration `split_words:"true"`

	// BackoffRandomizationFactor is VSO_BACKOFF_RANDOMIZATION_FACTOR environment variable option
	BackoffRandomizationFactor float64 `split_words:"true"`

	// BackoffMultiplier is VSO_BACKOFF_MULTIPLIER environment variable option
	BackoffMultiplier float64 `split_words:"true"`
}

// Parse environment variable options, prefixed with "VSO_"
func (c *VSOEnvOptions) Parse() error {
	return envconfig.Process("vso", c)
}
