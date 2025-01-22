// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/helpers"
)

var _ runtime.ClientTransport = (*fakeHVSTransport)(nil)

type fakeHVSTransportOpts struct {
	openSecretResponses  []*hvsclient.OpenAppSecretOK
	openSecretsResponses []*hvsclient.OpenAppSecretsOK
	listSecretsResponses []*hvsclient.ListAppSecretsOK
}

// fakeHVSTransport is used to fake responses from HVS in tests.
type fakeHVSTransport struct {
	t                    *testing.T
	openSecretResponses  []*hvsclient.OpenAppSecretOK
	openSecretsResponses []*hvsclient.OpenAppSecretsOK
	listSecretsResponses []*hvsclient.ListAppSecretsOK
	lastOpenSecretsIdx   int
	lastListSecretsIdx   int
	numRequests          int
}

func (f *fakeHVSTransport) Submit(operation *runtime.ClientOperation) (any, error) {
	f.t.Helper()

	f.numRequests++
	switch operation.ID {
	case "ListAppSecrets":
		if f.lastListSecretsIdx >= len(f.listSecretsResponses) {
			return &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{
					Pagination: nil,
				},
			}, nil
		}
		resp := f.listSecretsResponses[f.lastListSecretsIdx]
		f.lastListSecretsIdx++
		return resp, nil
	case "OpenAppSecrets":
		if f.lastOpenSecretsIdx >= len(f.openSecretsResponses) {
			return &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Pagination: nil,
				},
			}, nil
		}
		resp := f.openSecretsResponses[f.lastOpenSecretsIdx]
		f.lastOpenSecretsIdx++
		return resp, nil
	case "OpenAppSecret":
		params := operation.Params.(*hvsclient.OpenAppSecretParams)
		for _, resp := range f.openSecretResponses {
			if resp.Payload.Secret.Name == params.SecretName {
				return resp, nil
			}
		}
		return nil, fmt.Errorf(
			`[%s %s][%d]`, operation.Method, operation.PathPattern, http.StatusNotFound)
	default:
		return nil, fmt.Errorf("unsupported operation ID: %s", operation.ID)
	}
}

func newFakeHVSTransportWithOpts(t *testing.T, opt *fakeHVSTransportOpts) *fakeHVSTransport {
	t.Helper()

	p := &fakeHVSTransport{
		t: t,
	}
	if opt != nil {
		p.openSecretResponses = opt.openSecretResponses
		p.openSecretsResponses = opt.openSecretsResponses
		p.listSecretsResponses = opt.listSecretsResponses
	}
	return p
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

	var listSecrets []*models.Secrets20231128Secret
	for _, secret := range []*models.Secrets20231128OpenSecret{exampleStatic, exampleDynamic1, exampleDynamic2} {
		b, err := secret.MarshalBinary()
		require.NoError(t, err)
		s := &models.Secrets20231128Secret{}
		require.NoError(t, s.UnmarshalBinary(b))
		listSecrets = append(listSecrets, s)
	}

	tests := map[string]struct {
		expected        []*models.Secrets20231128OpenSecret
		opts            *fakeHVSTransportOpts
		wantNumRequests int
	}{
		"mixed": {
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: []*hvsclient.ListAppSecretsOK{
					{
						Payload: &models.Secrets20231128ListAppSecretsResponse{
							Secrets: listSecrets,
						},
					},
				},
				openSecretResponses: []*hvsclient.OpenAppSecretOK{
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleStatic,
						},
					},
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleDynamic1,
						},
					},
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleDynamic2,
						},
					},
				},
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1,
				exampleDynamic2,
			},
			wantNumRequests: 3,
		},
		"mixed-skip-not-found-after-list": {
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: []*hvsclient.ListAppSecretsOK{
					{
						Payload: &models.Secrets20231128ListAppSecretsResponse{
							Secrets: append(listSecrets,
								&models.Secrets20231128Secret{
									Name: "dynamic3",
									DynamicConfig: &models.Secrets20231128SecretDynamicConfig{
										TTL: "1h",
									},
									Type: "dynamic",
								},
							),
						},
					},
				},
				openSecretResponses: []*hvsclient.OpenAppSecretOK{
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleStatic,
						},
					},
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleDynamic1,
						},
					},
					{
						Payload: &models.Secrets20231128OpenAppSecretResponse{
							Secret: exampleDynamic2,
						},
					},
				},
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1,
				exampleDynamic2,
			},
			wantNumRequests: 4,
		},
		"no dynamic": {
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: []*hvsclient.ListAppSecretsOK{
					{
						Payload: &models.Secrets20231128ListAppSecretsResponse{
							Secrets: []*models.Secrets20231128Secret{
								listSecrets[0],
							},
						},
					},
				},
			},
			expected:        nil,
			wantNumRequests: 1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := newFakeHVSTransportWithOpts(t, tt.opts)
			client := hvsclient.New(p, nil)
			resp, err := getHVSDynamicSecrets(context.Background(), client,
				"appName", defaultDynamicRenewPercent, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp.secrets)
			assert.Equal(t, tt.wantNumRequests, p.numRequests)
		})
	}
}

func Test_getHVSDynamicSecrets_withShadowSecrets(t *testing.T) {
	t.Parallel()

	now := time.Now()

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
		Type:      "dynamic",
		CreatedAt: strfmt.DateTime(now),
	}

	// This version has a different top-level CreatedAt time than
	// exampleDynamic1 as though the dynamic secret was deleted and recreated
	// with the same name in HVS
	exampleDynamic1ReCreated := &models.Secrets20231128OpenSecret{
		Name: exampleDynamic1.Name,
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "recreatedkey1",
				"secret_id":  "recreatedid1",
			},
		},
		Type:      "dynamic",
		CreatedAt: strfmt.DateTime(now.Add(1 * time.Second)),
	}

	// This version has a different top-level LatestVersion than exampleDynamic1
	exampleDynamic1NewVersion := &models.Secrets20231128OpenSecret{
		Name: exampleDynamic1.Name,
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "newversionkey1",
				"secret_id":  "newversionid1",
			},
		},
		Type:          "dynamic",
		CreatedAt:     strfmt.DateTime(now),
		LatestVersion: 1,
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

	exampleShadow1Expired := &models.Secrets20231128OpenSecret{
		Name: exampleDynamic1.Name,
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "oldkey1",
				"secret_id":  "oldid1",
			},
			CreatedAt: strfmt.DateTime(now.Add(-1 * time.Hour)),
			ExpiresAt: strfmt.DateTime(now),
			TTL:       "3600s",
		},
		Type: "dynamic",
	}

	exampleShadow1NotExpired := &models.Secrets20231128OpenSecret{
		Name: exampleDynamic1.Name,
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			Values: map[string]string{
				"secret_key": "oldkey1",
				"secret_id":  "oldid1",
			},
			CreatedAt: strfmt.DateTime(now),
			ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
			TTL:       "3600s",
		},
		Type:      "dynamic",
		CreatedAt: strfmt.DateTime(now),
	}

	tests := map[string]struct {
		shadowSecrets   map[string]*models.Secrets20231128OpenSecret
		secretResponses []*models.Secrets20231128OpenSecret
		expected        []*models.Secrets20231128OpenSecret
		wantNumRequests int
	}{
		"one new and one ready for renewal": {
			shadowSecrets: map[string]*models.Secrets20231128OpenSecret{
				exampleShadow1Expired.Name: exampleShadow1Expired,
			},
			secretResponses: []*models.Secrets20231128OpenSecret{
				exampleStatic,
				exampleDynamic1,
				exampleDynamic2,
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1,
				exampleDynamic2,
			},
			wantNumRequests: 3,
		},
		"one new and one not ready for renewal": {
			shadowSecrets: map[string]*models.Secrets20231128OpenSecret{
				"dynamic1": exampleShadow1NotExpired,
			},
			secretResponses: []*models.Secrets20231128OpenSecret{
				exampleStatic,
				exampleDynamic1,
				exampleDynamic2,
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleShadow1NotExpired,
				exampleDynamic2,
			},
			wantNumRequests: 2,
		},
		"old shadow secret no longer in HVS": {
			shadowSecrets: map[string]*models.Secrets20231128OpenSecret{
				"dynamic1": exampleShadow1NotExpired,
			},
			secretResponses: []*models.Secrets20231128OpenSecret{
				exampleStatic,
			},
			expected:        nil,
			wantNumRequests: 1,
		},
		"one recreated since last reconcile": {
			shadowSecrets: map[string]*models.Secrets20231128OpenSecret{
				"dynamic1": exampleShadow1NotExpired,
			},
			secretResponses: []*models.Secrets20231128OpenSecret{
				exampleStatic,
				exampleDynamic1ReCreated,
				exampleDynamic2,
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1ReCreated,
				exampleDynamic2,
			},
			wantNumRequests: 3,
		},
		"one new version since last reconcile": {
			shadowSecrets: map[string]*models.Secrets20231128OpenSecret{
				"dynamic1": exampleShadow1NotExpired,
			},
			secretResponses: []*models.Secrets20231128OpenSecret{
				exampleStatic,
				exampleDynamic1NewVersion,
				exampleDynamic2,
			},
			expected: []*models.Secrets20231128OpenSecret{
				exampleDynamic1NewVersion,
				exampleDynamic2,
			},
			wantNumRequests: 3,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Construct the fake transport opts from the secrets in secretResponses
			opts := &fakeHVSTransportOpts{}
			var listSecrets []*models.Secrets20231128Secret
			for _, secret := range tt.secretResponses {
				b, err := secret.MarshalBinary()
				require.NoError(t, err)
				s := &models.Secrets20231128Secret{}
				require.NoError(t, s.UnmarshalBinary(b))
				listSecrets = append(listSecrets, s)
				opts.openSecretResponses = append(opts.openSecretResponses, &hvsclient.OpenAppSecretOK{
					Payload: &models.Secrets20231128OpenAppSecretResponse{
						Secret: secret,
					},
				})
			}
			opts.listSecretsResponses = []*hvsclient.ListAppSecretsOK{
				{
					Payload: &models.Secrets20231128ListAppSecretsResponse{
						Secrets: listSecrets,
					},
				},
			}
			p := newFakeHVSTransportWithOpts(t, opts)
			c := hvsclient.New(p, nil)

			// Run the dynamic secrets scenario with the given shadow/cached secrets
			resp, err := getHVSDynamicSecrets(context.Background(), c,
				"appName", defaultDynamicRenewPercent, tt.shadowSecrets)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp.secrets)
			assert.Equal(t, tt.wantNumRequests, p.numRequests)
		})
	}
}

func Test_getTimeToNextRenewal(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := map[string]struct {
		currentRenewal  nextRenewalDetails
		dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance
		renewPercent    int
		expected        nextRenewalDetails
	}{
		"new dynamic secret": {
			// A new dynamic secret is being evaluated, and its renewal is
			// before current next renewal
			currentRenewal: nextRenewalDetails{
				timeToNextRenewal: 2 * time.Hour,
				ttl:               135 * time.Minute,
			},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected: nextRenewalDetails{
				timeToNextRenewal: 40*time.Minute + 12*time.Second, // 1h*0.67
				ttl:               1 * time.Hour,
			},
		},
		"mid-ttl of the dynamic secret": {
			// The dynamic secret is halfway through its TTL, and the its
			// renewal should come before the current nextRenewal, so the
			// expected renewal time is 82% of the TTL (49m12s) minus the time
			// since the secret was created (30m).
			currentRenewal: nextRenewalDetails{
				timeToNextRenewal: 2 * time.Hour,
				ttl:               135 * time.Minute,
			},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-30 * time.Minute)),
				ExpiresAt: strfmt.DateTime(now.Add(30 * time.Minute)),
				TTL:       "3600s",
			},
			renewPercent: 82,
			expected: nextRenewalDetails{
				timeToNextRenewal: time.Duration(19*time.Minute + 12*time.Second), // 1h*0.82 - 30m
				ttl:               1 * time.Hour,
			},
		},
		"current next renewal is first": {
			currentRenewal: nextRenewalDetails{
				timeToNextRenewal: 1 * time.Hour,
				ttl:               90 * time.Minute,
			},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "7200s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected: nextRenewalDetails{
				timeToNextRenewal: 1 * time.Hour,
				ttl:               90 * time.Minute,
			},
		},
		"expired dynamic secret": {
			// Somehow this dynamic secret expired an hour ago, so it takes the
			// next renewal slot with the defaultDynamicRequeue time
			currentRenewal: nextRenewalDetails{
				timeToNextRenewal: 1 * time.Hour,
				ttl:               90 * time.Minute,
			},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-2 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(-1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected: nextRenewalDetails{
				timeToNextRenewal: defaultDynamicRequeue,
				ttl:               1 * time.Hour,
			},
		},
		"future dynamic secret": {
			currentRenewal: nextRenewalDetails{
				timeToNextRenewal: 1 * time.Hour,
				ttl:               90 * time.Minute,
			},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected: nextRenewalDetails{
				timeToNextRenewal: 1 * time.Hour,
				ttl:               90 * time.Minute,
			},
		},
		"currentRenewal is blank": {
			currentRenewal: nextRenewalDetails{},
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected: nextRenewalDetails{
				timeToNextRenewal: 40*time.Minute + 12*time.Second, // 1h*0.67
				ttl:               1 * time.Hour,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getTimeToNextRenewal(tc.currentRenewal, tc.dynamicInstance, tc.renewPercent, now)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func Test_timeForRenewal(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := map[string]struct {
		dynamicInstance *models.Secrets20231128OpenSecretDynamicInstance
		renewPercent    int
		expected        bool
	}{
		"new dynamic secret": {
			// A fairly new dynamic secret is being evaluated
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-5 * time.Minute)),
				ExpiresAt: strfmt.DateTime(now.Add(55 * time.Minute)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected:     false,
		},
		"mid-ttl of the dynamic secret": {
			// The dynamic secret is halfway through its TTL, which is less than
			// 82% of its TTL
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-30 * time.Minute)),
				ExpiresAt: strfmt.DateTime(now.Add(30 * time.Minute)),
				TTL:       "3600s",
			},
			renewPercent: 82,
			expected:     false,
		},
		"past renewal percent point": {
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-45 * time.Minute)),
				ExpiresAt: strfmt.DateTime(now.Add(15 * time.Minute)),
				TTL:       "3600s",
			},
			renewPercent: 70,
			expected:     true,
		},
		"expired dynamic secret": {
			// Somehow this dynamic secret expired an hour ago, so definitely
			// time to renew it
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(-2 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(-1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected:     true,
		},
		"future dynamic secret": {
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected:     false,
		},
		"no dynamic secret metadata": {
			dynamicInstance: nil,
			renewPercent:    defaultDynamicRenewPercent,
			expected:        true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := timeForRenewal(tc.dynamicInstance, tc.renewPercent, now)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func Test_makeDynamicRenewPercent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		syncConfig *secretsv1beta1.HVSSyncConfig
		expected   int
	}{
		"syncConfig is nil": {
			syncConfig: nil,
			expected:   defaultDynamicRenewPercent,
		},
		"syncConfig.Dynamic is nil": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: nil,
			},
			expected: defaultDynamicRenewPercent,
		},
		"syncConfig.Dynamic not nil": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: &secretsv1beta1.HVSDynamicSyncConfig{
					RenewalPercent: 42,
				},
			},
			expected: 42,
		},
		"syncConfig.Dynamic.RenewalPercent is over 90": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: &secretsv1beta1.HVSDynamicSyncConfig{
					RenewalPercent: 91,
				},
			},
			expected: 90,
		},
		"syncConfig.Dynamic.RenewalPercent is under 0": {
			syncConfig: &secretsv1beta1.HVSSyncConfig{
				Dynamic: &secretsv1beta1.HVSDynamicSyncConfig{
					RenewalPercent: -1,
				},
			},
			expected: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := getDynamicRenewPercent(tc.syncConfig)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func Test_fetchOpenSecretsPaginated(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fooSecret := &models.Secrets20231128OpenSecret{
		Name: "foo",
		Type: helpers.HVSSecretTypeKV,
	}
	dynSecret := &models.Secrets20231128OpenSecret{
		Name: "dyn",
		Type: helpers.HVSSecretTypeDynamic,
		DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
			TTL: "1h",
		},
	}
	barSecret := &models.Secrets20231128OpenSecret{
		Name: "bar",
		Type: helpers.HVSSecretTypeKV,
	}

	bazSecret := &models.Secrets20231128OpenSecret{
		Name: "baz",
		Type: helpers.HVSSecretTypeKV,
	}

	allSecrets := []*models.Secrets20231128OpenSecret{
		fooSecret,
		dynSecret,
		barSecret,
		bazSecret,
	}
	listResponsesEmptyPageToken := []*hvsclient.OpenAppSecretsOK{
		{
			Payload: &models.Secrets20231128OpenAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{
					NextPageToken: "page1",
				},
				Secrets: []*models.Secrets20231128OpenSecret{
					fooSecret,
					dynSecret,
				},
			},
		},
		{
			Payload: &models.Secrets20231128OpenAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{
					NextPageToken: "page2",
				},
				Secrets: []*models.Secrets20231128OpenSecret{
					barSecret,
				},
			},
		},
		{
			Payload: &models.Secrets20231128OpenAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{},
				Secrets: []*models.Secrets20231128OpenSecret{
					bazSecret,
				},
			},
		},
	}

	var listResponseNilPagination []*hvsclient.OpenAppSecretsOK
	for _, response := range listResponsesEmptyPageToken {
		require.NotNil(t, response.Payload.Pagination)

		payload := &models.Secrets20231128OpenAppSecretsResponse{
			Pagination: response.Payload.Pagination,
			Secrets:    response.Payload.Secrets,
		}
		if response.Payload.Pagination.NextPageToken == "" {
			payload.Pagination = nil
		}

		listResponseNilPagination = append(listResponseNilPagination, &hvsclient.OpenAppSecretsOK{
			Payload: payload,
		})
	}

	tests := []struct {
		name            string
		params          *hvsclient.OpenAppSecretsParams
		filter          openSecretFilter
		opts            *fakeHVSTransportOpts
		wantNumRequests int
		want            *hvsclient.OpenAppSecretsOK
		wantErr         assert.ErrorAssertionFunc
	}{
		{
			name:    "nil-params",
			wantErr: assert.Error,
		},
		{
			name: "empty",
			params: &hvsclient.OpenAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				openSecretsResponses: []*hvsclient.OpenAppSecretsOK{
					{
						Payload: &models.Secrets20231128OpenAppSecretsResponse{
							Secrets: nil,
						},
					},
				},
			},
			want: &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Secrets: nil,
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 1,
		},
		{
			name: "one-page",
			params: &hvsclient.OpenAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				openSecretsResponses: []*hvsclient.OpenAppSecretsOK{
					{
						Payload: &models.Secrets20231128OpenAppSecretsResponse{
							Secrets: []*models.Secrets20231128OpenSecret{
								fooSecret,
							},
						},
					},
				},
			},
			want: &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Secrets: []*models.Secrets20231128OpenSecret{
						fooSecret,
					},
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 1,
		},
		{
			name: "multi-page-nil-pagination",
			params: &hvsclient.OpenAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				openSecretsResponses: listResponseNilPagination,
			},
			want: &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Secrets: allSecrets,
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
		{
			name: "multi-page-empty-next-page-token-filtered",
			filter: func(secret *models.Secrets20231128OpenSecret) bool {
				return secret.Type != helpers.HVSSecretTypeKV
			},
			params: &hvsclient.OpenAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				openSecretsResponses: listResponsesEmptyPageToken,
			},
			want: &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Pagination: &models.CommonPaginationResponse{},
					Secrets: []*models.Secrets20231128OpenSecret{
						dynSecret,
					},
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
		{
			name: "multi-page-empty-next-page-token",
			params: &hvsclient.OpenAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				openSecretsResponses: listResponsesEmptyPageToken,
			},
			want: &hvsclient.OpenAppSecretsOK{
				Payload: &models.Secrets20231128OpenAppSecretsResponse{
					Pagination: &models.CommonPaginationResponse{},
					Secrets:    allSecrets,
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newFakeHVSTransportWithOpts(t, tt.opts)
			c := hvsclient.New(p, nil)
			got, err := fetchOpenSecretsPaginated(ctx, c, tt.params, tt.filter)
			if !tt.wantErr(t, err, fmt.Sprintf("openSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)) {
				return
			}
			assert.Equalf(t, tt.want, got, "openSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)
			assert.Equalf(t, tt.wantNumRequests, p.numRequests, "openSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)
		})
	}
}

func Test_listSecretsPaginated(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	fooSecret := &models.Secrets20231128Secret{
		Name: "foo",
		Type: helpers.HVSSecretTypeKV,
	}
	dynSecret := &models.Secrets20231128Secret{
		Name: "dyn",
		Type: helpers.HVSSecretTypeDynamic,
		DynamicConfig: &models.Secrets20231128SecretDynamicConfig{
			TTL: "1h",
		},
	}
	barSecret := &models.Secrets20231128Secret{
		Name: "bar",
		Type: helpers.HVSSecretTypeKV,
	}

	bazSecret := &models.Secrets20231128Secret{
		Name: "baz",
		Type: helpers.HVSSecretTypeKV,
	}

	allSecrets := []*models.Secrets20231128Secret{
		fooSecret,
		dynSecret,
		barSecret,
		bazSecret,
	}
	listResponsesEmptyPageToken := []*hvsclient.ListAppSecretsOK{
		{
			Payload: &models.Secrets20231128ListAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{
					NextPageToken: "page1",
				},
				Secrets: []*models.Secrets20231128Secret{
					fooSecret,
					dynSecret,
				},
			},
		},
		{
			Payload: &models.Secrets20231128ListAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{
					NextPageToken: "page2",
				},
				Secrets: []*models.Secrets20231128Secret{
					barSecret,
				},
			},
		},
		{
			Payload: &models.Secrets20231128ListAppSecretsResponse{
				Pagination: &models.CommonPaginationResponse{},
				Secrets: []*models.Secrets20231128Secret{
					bazSecret,
				},
			},
		},
	}

	var listResponseNilPagination []*hvsclient.ListAppSecretsOK
	for _, response := range listResponsesEmptyPageToken {
		require.NotNil(t, response.Payload.Pagination)

		payload := &models.Secrets20231128ListAppSecretsResponse{
			Pagination: response.Payload.Pagination,
			Secrets:    response.Payload.Secrets,
		}
		if response.Payload.Pagination.NextPageToken == "" {
			payload.Pagination = nil
		}

		listResponseNilPagination = append(listResponseNilPagination, &hvsclient.ListAppSecretsOK{
			Payload: payload,
		})
	}

	tests := []struct {
		name            string
		params          *hvsclient.ListAppSecretsParams
		filter          secretFilter
		opts            *fakeHVSTransportOpts
		want            *hvsclient.ListAppSecretsOK
		wantNumRequests int
		wantErr         assert.ErrorAssertionFunc
	}{
		{
			name:    "nil-params",
			wantErr: assert.Error,
		},
		{
			name: "empty",
			params: &hvsclient.ListAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: []*hvsclient.ListAppSecretsOK{
					{
						Payload: &models.Secrets20231128ListAppSecretsResponse{},
					},
				},
			},
			want: &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 1,
		},
		{
			name: "one-page",
			params: &hvsclient.ListAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: []*hvsclient.ListAppSecretsOK{
					{
						Payload: &models.Secrets20231128ListAppSecretsResponse{
							Secrets: []*models.Secrets20231128Secret{
								fooSecret,
							},
						},
					},
				},
			},
			want: &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{
					Secrets: []*models.Secrets20231128Secret{
						fooSecret,
					},
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 1,
		},
		{
			name: "multi-page-nil-pagination",
			params: &hvsclient.ListAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: listResponseNilPagination,
			},
			want: &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{
					Secrets: allSecrets,
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
		{
			name: "multi-page-empty-next-page-token",
			params: &hvsclient.ListAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: listResponsesEmptyPageToken,
			},
			want: &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{
					Pagination: &models.CommonPaginationResponse{},
					Secrets:    allSecrets,
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
		{
			name: "multi-page-empty-next-page-token-filtered",
			filter: func(secret *models.Secrets20231128Secret) bool {
				// filter out all non KV secrets
				return secret.Type != helpers.HVSSecretTypeKV
			},
			params: &hvsclient.ListAppSecretsParams{
				Context: ctx,
			},
			opts: &fakeHVSTransportOpts{
				listSecretsResponses: listResponsesEmptyPageToken,
			},
			want: &hvsclient.ListAppSecretsOK{
				Payload: &models.Secrets20231128ListAppSecretsResponse{
					Pagination: &models.CommonPaginationResponse{},
					Secrets: []*models.Secrets20231128Secret{
						dynSecret,
					},
				},
			},
			wantErr:         assert.NoError,
			wantNumRequests: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newFakeHVSTransportWithOpts(t, tt.opts)
			c := hvsclient.New(p, nil)
			got, err := listSecretsPaginated(ctx, c, tt.params, tt.filter)
			if !tt.wantErr(t, err, fmt.Sprintf("listSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)) {
				return
			}

			assert.Equalf(t, tt.want, got, "listSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)
			assert.Equalf(t, tt.wantNumRequests, p.numRequests, "listSecretsPaginated(%v, %v, %v, %v)", ctx, c, tt.params, tt.filter)
		})
	}
}

func Test_parseHVSResponseError(t *testing.T) {
	t.Parallel()

	errorMessageFmt := `[%s %s][%d]`
	pathPattern := "/secrets/2024-11-28/organizations/{organization_id}/projects/{project_id}/apps/{app_name}/secrets:open"
	tests := []struct {
		name string
		err  error
		want *hvsResponseErrorStatus
	}{
		{
			name: "nil",
			err:  nil,
		},
		{
			name: "nil-no-match",
			err: errors.New(
				fmt.Sprintf(errorMessageFmt, http.MethodGet, pathPattern, http.StatusForbidden)[1:]),
		},
		{
			name: "status-error-forbidden-get",
			err:  fmt.Errorf(errorMessageFmt, http.MethodGet, pathPattern, http.StatusForbidden),
			want: &hvsResponseErrorStatus{
				Method:      http.MethodGet,
				PathPattern: pathPattern,
				StatusCode:  http.StatusForbidden,
			},
		},
		{
			name: "status-error-forbidden-post",
			err:  fmt.Errorf(errorMessageFmt, http.MethodPost, pathPattern, http.StatusForbidden),
			want: &hvsResponseErrorStatus{
				Method:      http.MethodPost,
				PathPattern: pathPattern,
				StatusCode:  http.StatusForbidden,
			},
		},
		{
			name: "status-error-not-found",
			err:  fmt.Errorf(errorMessageFmt, http.MethodGet, pathPattern, http.StatusNotFound),
			want: &hvsResponseErrorStatus{
				Method:      http.MethodGet,
				PathPattern: pathPattern,
				StatusCode:  http.StatusNotFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parseHVSResponseError(tt.err), "parseHVSResponseError(%v)", tt.err)
		})
	}
}

func Test_makeShadowObjKey(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		o    *secretsv1beta1.HCPVaultSecretsApp
		want client.ObjectKey
	}{
		"normal": {
			o: &secretsv1beta1.HCPVaultSecretsApp{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns",
					Name:      "name",
				},
			},
			want: client.ObjectKey{
				Namespace: common.OperatorNamespace,
				Name:      shadowSecretPrefix + "-" + helpers.HashString("ns-name"),
			},
		},
		"long-name": {
			o: &secretsv1beta1.HCPVaultSecretsApp{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mytestnamespace",
					Name:      strings.Repeat("a", 63),
				},
			},
			want: client.ObjectKey{
				Namespace: common.OperatorNamespace,
				Name: fmt.Sprintf("%s-%s", shadowSecretPrefix,
					helpers.HashString("mytestnamespace-"+strings.Repeat("a", 63))),
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, makeShadowObjKey(tt.o))
		})
	}
}

func Test_CleanupOrphanedShadowSecrets(t *testing.T) {
	deletionTimestamp := metav1.Now()

	hvsApp := secretsv1beta1.HCPVaultSecretsApp{
		TypeMeta: metav1.TypeMeta{
			Kind:       HCPVaultSecretsApp.String(),
			APIVersion: secretsv1beta1.GroupVersion.Version,
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "hvs-app-ns",
			Name:       "hvs-app",
			Finalizers: []string{hcpVaultSecretsAppFinalizer},
		},
	}

	tests := map[string]struct {
		o                                    *secretsv1beta1.HCPVaultSecretsApp
		secret                               *corev1.Secret
		isHCPVaultSecretsAppDeletionExpected bool
		isShadowSecretDeletionExpected       bool
	}{
		"HCPVaultSecretsApp and shadow secret marked for deletion, HCPVaultSecretsApp is owner of shadow secret": {
			o: hvsApp.DeepCopy(),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         common.OperatorNamespace,
					Name:              "shadow-secret",
					DeletionTimestamp: &deletionTimestamp,
					Finalizers:        []string{vaultDynamicSecretFinalizer},
					Labels: map[string]string{
						hvsaLabelPrefix + "/name":      hvsApp.GetName(),
						hvsaLabelPrefix + "/namespace": hvsApp.GetNamespace(),
						"app.kubernetes.io/component":  "hvs-dynamic-secret-cache",
						helpers.LabelOwnerRefUID:       string(hvsApp.GetUID()),
					},
				},
			},
			isHCPVaultSecretsAppDeletionExpected: true,
			isShadowSecretDeletionExpected:       true,
		},
		"HCPVaultSecretsApp not owner of shadow secret, shadow secret marked for deletion": {
			o: hvsApp.DeepCopy(),
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         common.OperatorNamespace,
					Name:              "shadow-secret",
					DeletionTimestamp: &deletionTimestamp,
					Finalizers:        []string{vaultDynamicSecretFinalizer},
					Labels: map[string]string{
						"app.kubernetes.io/component": "hvs-dynamic-secret-cache",
					},
				},
			},
			isShadowSecretDeletionExpected: true,
		},
		"HCPVaultSecretsApp not found, shadow secret marked for deletion": {
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: common.OperatorNamespace,
					Name:      "shadow-secret",
					Labels: map[string]string{
						"app.kubernetes.io/component": "hvs-dynamic-secret-cache",
					},
					DeletionTimestamp: &deletionTimestamp,
					Finalizers:        []string{hcpVaultSecretsAppFinalizer},
				},
			},
			isShadowSecretDeletionExpected: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			scheme := ctrlruntime.NewScheme()
			corev1.AddToScheme(scheme)
			secretsv1beta1.AddToScheme(scheme)

			client := fake.NewClientBuilder().WithObjects(tt.secret).WithScheme(scheme).Build()
			r := &HCPVaultSecretsAppReconciler{
				Client:          client,
				BackOffRegistry: NewBackOffRegistry(),
				referenceCache:  newResourceReferenceCache(),
			}

			ctx := context.Background()

			if tt.o != nil {
				assert.NoError(t, client.Create(ctx, tt.o))
			}

			// DeleteTimestamp is a read-only field, so Delete will need to be called to
			// simulate deletion of the HCPVaultSecretsApp
			if tt.isHCPVaultSecretsAppDeletionExpected {
				assert.NoError(t, client.Delete(ctx, tt.o))
			}

			err := r.cleanupOrphanedShadowSecrets(ctx)
			assert.NoError(t, err)

			// confirm that the HCPVaultSecretsApp and shadow secret were successfully deleted if expected
			if tt.isHCPVaultSecretsAppDeletionExpected {
				deletedHVSApp := &secretsv1beta1.HCPVaultSecretsApp{}
				err = client.Get(ctx, makeShadowObjKey(tt.o), deletedHVSApp)
				assert.True(t, apierrors.IsNotFound(err))
			}

			if tt.isShadowSecretDeletionExpected {
				deletedSecret := &corev1.Secret{}
				err = client.Get(ctx, makeShadowObjKey(tt.secret), deletedSecret)
				assert.True(t, apierrors.IsNotFound(err))
			}
		})
	}
}
