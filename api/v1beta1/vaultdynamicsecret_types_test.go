// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultDynamicSecret_DeepCopy_SyncConfig(t *testing.T) {
	t.Run("nil-syncconfig", func(t *testing.T) {
		o := &VaultDynamicSecret{
			Spec: VaultDynamicSecretSpec{
				Mount: "database",
				Path:  "static-creds/myrole",
			},
		}
		c := o.DeepCopy()
		require.NotNil(t, c)
		assert.Nil(t, c.Spec.SyncConfig)
	})

	t.Run("populated-syncconfig", func(t *testing.T) {
		o := &VaultDynamicSecret{
			Spec: VaultDynamicSecretSpec{
				Mount: "database",
				Path:  "static-creds/myrole",
				SyncConfig: &VaultDynamicSecretSyncConfig{
					InstantUpdates: true,
					EngineType:     "database",
				},
			},
		}
		c := o.DeepCopy()
		require.NotNil(t, c)
		require.NotNil(t, c.Spec.SyncConfig)
		assert.NotSame(t, o.Spec.SyncConfig, c.Spec.SyncConfig)
		assert.Equal(t, o.Spec.SyncConfig.InstantUpdates, c.Spec.SyncConfig.InstantUpdates)
		assert.Equal(t, o.Spec.SyncConfig.EngineType, c.Spec.SyncConfig.EngineType)

		c.Spec.SyncConfig.InstantUpdates = false
		c.Spec.SyncConfig.EngineType = "ldap"
		assert.True(t, o.Spec.SyncConfig.InstantUpdates,
			"original mutated when copy was modified")
		assert.Equal(t, "database", o.Spec.SyncConfig.EngineType,
			"original engineType mutated when copy was modified")
	})
}
