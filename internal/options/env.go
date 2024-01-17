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

	// MaxConcurrentReconcilesVDS is the VSO_MAX_CONCURRENT_RECONCILES_VDS environment variable option
	MaxConcurrentReconcilesVDS *int `split_words:"true"`

	// MinRefreshAfterHVSA is the VSO_MIN_REFRESH_AFTER_HVSA environment variable option
	MinRefreshAfterHVSA time.Duration `envconfig:"min_refresh_after_hvsa"`
}

// Parse environment variable options, prefixed with "VSO_"
func (c *VSOEnvOptions) Parse() error {
	return envconfig.Process("vso", c)
}
