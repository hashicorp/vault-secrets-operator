// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package testutils

import (
	"testing"

	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	"github.com/stretchr/testify/assert"
)

func CheckDynamicOpenSecretEqual(t *testing.T, want, got *models.Secrets20231128OpenSecret) {
	t.Helper()

	assert.Equal(t, want.CreatedAt.String(), got.CreatedAt.String())
	assert.Equal(t, want.CreatedByID, got.CreatedByID)
	assert.Equal(t, want.LatestVersion, got.LatestVersion)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Provider, got.Provider)
	assert.Equal(t, want.SyncStatus, got.SyncStatus)
	assert.Equal(t, want.Type, got.Type)

	assert.Equal(t, want.DynamicInstance.CreatedAt.String(),
		got.DynamicInstance.CreatedAt.String())
	assert.Equal(t, want.DynamicInstance.ExpiresAt.String(),
		got.DynamicInstance.ExpiresAt.String())
	assert.Equal(t, want.DynamicInstance.TTL, got.DynamicInstance.TTL)
	assert.Equal(t, want.DynamicInstance.Values, got.DynamicInstance.Values)
}
