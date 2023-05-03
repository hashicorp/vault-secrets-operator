// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"testing"
	"time"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func Test_inRenewalWindow(t *testing.T) {
	tests := map[string]struct {
		status           secretsv1alpha1.VaultDynamicSecretStatus
		expectedInWindow bool
	}{
		"full lease elapsed": {
			status: secretsv1alpha1.VaultDynamicSecretStatus{
				SecretLease: secretsv1alpha1.VaultSecretLease{
					LeaseDuration: 600,
				},
				LastRenewalTime: time.Now().Unix() - 600,
			},
			expectedInWindow: true,
		},
		"two thirds elapsed": {
			status: secretsv1alpha1.VaultDynamicSecretStatus{
				SecretLease: secretsv1alpha1.VaultSecretLease{
					LeaseDuration: 600,
				},
				LastRenewalTime: time.Now().Unix() - 400,
			},
			expectedInWindow: true,
		},
		"one third elapsed": {
			status: secretsv1alpha1.VaultDynamicSecretStatus{
				SecretLease: secretsv1alpha1.VaultSecretLease{
					LeaseDuration: 600,
				},
				LastRenewalTime: time.Now().Unix() - 200,
			},
			expectedInWindow: false,
		},
		"past end of lease": {
			status: secretsv1alpha1.VaultDynamicSecretStatus{
				SecretLease: secretsv1alpha1.VaultSecretLease{
					LeaseDuration: 600,
				},
				LastRenewalTime: time.Now().Unix() - 800,
			},
			expectedInWindow: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expectedInWindow, inRenewalWindow(tc.status))
		})
	}
}
