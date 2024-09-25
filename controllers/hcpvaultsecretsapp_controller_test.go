// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
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
			resp, err := getHVSDynamicSecrets(context.Background(), client, "appName")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp)
			assert.Equal(t, tt.wantNumRequests, p.numRequests)
		})
	}
}

func Test_getNextRequeue(t *testing.T) {
	t.Parallel()

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
			renewPercent: defaultDynamicRenewPercent,
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
			renewPercent: defaultDynamicRenewPercent,
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
			renewPercent: defaultDynamicRenewPercent,
			expected:     defaultDynamicRequeue,
		},
		"future dynamic secret": {
			requeueAfter: 1 * time.Hour,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				ExpiresAt: strfmt.DateTime(now.Add(2 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected:     1 * time.Hour,
		},
		"reqeueAfter is zero": {
			requeueAfter: 0,
			dynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				TTL:       "3600s",
			},
			renewPercent: defaultDynamicRenewPercent,
			expected:     time.Duration(40*time.Minute + 12*time.Second), // 1h*0.67
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

func Test_parseHVSErrorResponse(t *testing.T) {
	t.Parallel()

	errorMessageFmt := `[%s %s][%d]`
	pathPattern := "/secrets/2024-11-28/organizations/{organization_id}/projects/{project_id}/apps/{app_name}/secrets:open"
	tests := []struct {
		name string
		err  error
		want *hvsErrorResponse
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
			want: &hvsErrorResponse{
				Method:      http.MethodGet,
				PathPattern: pathPattern,
				StatusCode:  http.StatusForbidden,
			},
		},
		{
			name: "status-error-forbidden-post",
			err:  fmt.Errorf(errorMessageFmt, http.MethodPost, pathPattern, http.StatusForbidden),
			want: &hvsErrorResponse{
				Method:      http.MethodPost,
				PathPattern: pathPattern,
				StatusCode:  http.StatusForbidden,
			},
		},
		{
			name: "status-error-not-found",
			err:  fmt.Errorf(errorMessageFmt, http.MethodGet, pathPattern, http.StatusNotFound),
			want: &hvsErrorResponse{
				Method:      http.MethodGet,
				PathPattern: pathPattern,
				StatusCode:  http.StatusNotFound,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parseHVSErrorResponse(tt.err), "parseHVSErrorResponse(%v)", tt.err)
		})
	}
}
