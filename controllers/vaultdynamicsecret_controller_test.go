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
		vds              *secretsv1alpha1.VaultDynamicSecret
		expectedInWindow bool
	}{
		"full lease elapsed": {
			vds: &secretsv1alpha1.VaultDynamicSecret{
				Status: secretsv1alpha1.VaultDynamicSecretStatus{
					SecretLease: secretsv1alpha1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 600,
				},
				Spec: secretsv1alpha1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"two thirds elapsed": {
			vds: &secretsv1alpha1.VaultDynamicSecret{
				Status: secretsv1alpha1.VaultDynamicSecretStatus{
					SecretLease: secretsv1alpha1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 450,
				},
				Spec: secretsv1alpha1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"one third elapsed": {
			vds: &secretsv1alpha1.VaultDynamicSecret{
				Status: secretsv1alpha1.VaultDynamicSecretStatus{
					SecretLease: secretsv1alpha1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 200,
				},
				Spec: secretsv1alpha1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: false,
		},
		"past end of lease": {
			vds: &secretsv1alpha1.VaultDynamicSecret{
				Status: secretsv1alpha1.VaultDynamicSecretStatus{
					SecretLease: secretsv1alpha1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 800,
				},
				Spec: secretsv1alpha1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"renewalPercent is 0": {
			vds: &secretsv1alpha1.VaultDynamicSecret{
				Status: secretsv1alpha1.VaultDynamicSecretStatus{
					SecretLease: secretsv1alpha1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 400,
				},
				Spec: secretsv1alpha1.VaultDynamicSecretSpec{
					RenewalPercent: 0,
				},
			},
			expectedInWindow: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expectedInWindow, inRenewalWindow(tc.vds))
		})
	}
}
