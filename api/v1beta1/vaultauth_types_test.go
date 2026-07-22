// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultAuthConfigAppRole_Validate(t *testing.T) {
	tests := []struct {
		name      string
		appRole   *VaultAuthConfigAppRole
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid-with-secretref",
			appRole: &VaultAuthConfigAppRole{
				RoleID:    "test-role",
				SecretRef: "test-secret",
			},
			wantError: false,
		},
		{
			name: "invalid-missing-secretref",
			appRole: &VaultAuthConfigAppRole{
				RoleID: "test-role",
			},
			wantError: true,
			errorMsg:  "secretRef must be specified",
		},
		{
			name: "invalid-missing-roleid",
			appRole: &VaultAuthConfigAppRole{
				SecretRef: "test-secret",
			},
			wantError: true,
			errorMsg:  "empty roleID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.appRole.Validate()
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVaultAuthConfigAppRole_Merge(t *testing.T) {
	tests := []struct {
		name      string
		base      *VaultAuthConfigAppRole
		other     *VaultAuthConfigAppRole
		want      *VaultAuthConfigAppRole
		wantError bool
	}{
		{
			name: "merge-empty-fields",
			base: &VaultAuthConfigAppRole{
				RoleID: "base-role",
			},
			other: &VaultAuthConfigAppRole{
				RoleID:    "other-role",
				SecretRef: "other-secret",
			},
			want: &VaultAuthConfigAppRole{
				RoleID:    "base-role",
				SecretRef: "other-secret",
			},
			wantError: false,
		},
		{
			name: "merge-preserves-base-values",
			base: &VaultAuthConfigAppRole{
				RoleID:    "base-role",
				SecretRef: "base-secret",
			},
			other: &VaultAuthConfigAppRole{
				RoleID:    "other-role",
				SecretRef: "other-secret",
			},
			want: &VaultAuthConfigAppRole{
				RoleID:    "base-role",
				SecretRef: "base-secret",
			},
			wantError: false,
		},
		{
			name: "merge-creates-invalid-config",
			base: &VaultAuthConfigAppRole{
				RoleID: "base-role",
			},
			other: &VaultAuthConfigAppRole{
				RoleID: "other-role",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.base.Merge(tt.other)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want.RoleID, got.RoleID)
				assert.Equal(t, tt.want.SecretRef, got.SecretRef)
			}
		})
	}
}
