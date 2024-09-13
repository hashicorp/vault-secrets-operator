// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ runtime.ClientTransport = (*fakeHVSTransport)(nil)

// fakeHVSTransport is used to fake responses from HVS in tests.
type fakeHVSTransport struct {
	secrets []*models.Secrets20231128OpenSecret
}

func (f *fakeHVSTransport) Submit(operation *runtime.ClientOperation) (interface{}, error) {
	if operation.ID == "ListAppSecrets" {
		respSecrets := []*models.Secrets20231128Secret{}
		for _, secret := range f.secrets {
			mb, err := secret.MarshalBinary()
			if err != nil {
				return nil, err
			}
			closedSecret := &models.Secrets20231128Secret{}
			err = closedSecret.UnmarshalBinary(mb)
			if err != nil {
				return nil, err
			}
			respSecrets = append(respSecrets, closedSecret)
		}
		return &hvsclient.ListAppSecretsOK{
			Payload: &models.Secrets20231128ListAppSecretsResponse{
				Secrets: respSecrets,
			},
		}, nil
	}

	if operation.ID == "OpenAppSecret" {
		params := operation.Params.(*hvsclient.OpenAppSecretParams)
		for _, secret := range f.secrets {
			if secret.Name == params.SecretName {
				return &hvsclient.OpenAppSecretOK{
					Payload: &models.Secrets20231128OpenAppSecretResponse{
						Secret: secret,
					},
				}, nil
			}
		}
		return nil, fmt.Errorf("secret %q not found", params.SecretName)
	}

	return nil, fmt.Errorf("unsupported operation ID: %s", operation.ID)
}

func newFakeHVSTransport(secrets []*models.Secrets20231128OpenSecret) *fakeHVSTransport {
	return &fakeHVSTransport{secrets: secrets}
}

func Test_getHVSDynamicSecrets(t *testing.T) {
	t.Parallel()

	exampleStatic := &models.Secrets20231128OpenSecret{
		Name: "static",
		StaticVersion: &models.Secrets20231128OpenSecretStaticVersion{
			Value: "value",
		},
		Type: "static",
	}

	exampleDynamic1 := &models.Secrets20231128OpenSecret{
		Name: "dynamic1",
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "key1",
				"secret_id":  "id1",
			},
		},
		Type: "dynamic",
	}

	exampleDynamic2 := &models.Secrets20231128OpenSecret{
		Name: "dynamic2",
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "key2",
				"secret_id":  "id2",
			},
		},
		Type: "dynamic",
	}

	tests := map[string]struct {
		hvsSecrets []*models.Secrets20231128OpenSecret
		expected   []*models.Secrets20231128OpenSecret
	}{
		"mixed": {
			hvsSecrets: []*models.Secrets20231128OpenSecret{
				exampleStatic,
				exampleDynamic1,
				exampleDynamic2,
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1,
				exampleDynamic2,
			},
		},
		"no dynamic": {
			hvsSecrets: []*models.Secrets20231128OpenSecret{
				exampleStatic,
			},
			expected: []*models.Secrets20231128OpenSecret{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			transport := newFakeHVSTransport(tt.hvsSecrets)
			client := hvsclient.New(transport, nil)
			resp, err := getHVSDynamicSecrets(context.Background(), client, "appName")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp)
		})
	}
}

func Test_getNextRequeue(t *testing.T) {
	now := time.Now()

	tests := map[string]struct {
		requeueAfter    time.Duration
		dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance
		renewPercent    int
		expected        time.Duration
	}{
		"new dynamic secret": {
			// A new dynamic secret is being evaluated, and its renewal is
			// before next requeueAfter
			requeueAfter: 2 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDyanmicRenewPercent,
			expected:     time.Duration(40*time.Minute + 12*time.Second), // 1h*0.67
		},
		"mid-ttl of the dynamic secret": {
			// The dynamic secret is halfway through its TTL, and the its
			// renewal should come before the current requeueAfter, so the
			// expected renewal time is 82% of the TTL (49m12s) minus the time
			// since the secret was created (30m).
			requeueAfter: 2 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-30 * time.Minute)),
				ExpiresAt: strfmt.DateTime(now.Add(30 * time.Minute)),
				TTL:       "3600s",
			},
			renewPercent: 82,
			expected:     time.Duration(19*time.Minute + 12*time.Second), // 1h*0.82 - 30m
		},
		"requeueAfter is shorter": {
			requeueAfter: 1 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "7200s",
			},
			renewPercent: defaultDyanmicRenewPercent,
			expected:     1 * time.Hour,
		},
		"expired dynamic secret": {
			// Somehow this dynamic secret expired an hour ago, so requeue
			// immediately.
			requeueAfter: 1 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-2 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(-1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDyanmicRenewPercent,
			expected:     1 * time.Second,
		},
		"future dynamic secret": {
			requeueAfter: 1 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDyanmicRenewPercent,
			expected:     1 * time.Hour,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getNextRequeue(tc.requeueAfter, tc.dynamicInstance, tc.renewPercent, now)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func Test_makeDynamicRenewPercent(t *testing.T) {
	tests := map[string]struct {
		syncConfig *secretsv1beta1.HVSSyncConfig
		expected   int
	}{
		"syncConfig is nil": {
			syncConfig: nil,
			expected:   defaultDyanmicRenewPercent,
		},
		"syncConfig.Dynamic is nil": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: nil,
			},
			expected: defaultDyanmicRenewPercent,
		},
		"syncConfig.Dynamic not nil": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: &secretsv1beta1.HVSDynamicSyncConfig{
					RenewalPercent: 42,
				},
			},
			expected: 42,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getDynamicRenewPercent(tc.syncConfig)
			assert.Equal(t, tc.expected, got)
		})
	}
}
