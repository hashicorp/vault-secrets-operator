// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/errors"
)

func TestServicePrincipleCredentialProvider_GetCreds(t *testing.T) {
	ctx := context.Background()
	authObj := &secretsv1beta1.HCPAuth{
		Spec: secretsv1beta1.HCPAuthSpec{
			Method: ProviderMethodServicePrincipal,
			ServicePrincipal: &secretsv1beta1.HCPAuthServicePrincipal{
				SecretRef: "foo",
			},
		},
	}

	tests := []struct {
		name              string
		authObj           *secretsv1beta1.HCPAuth
		secretData        map[string][]byte
		providerNamespace string
		want              map[string]any
		wantErr           assert.ErrorAssertionFunc
	}{
		{
			name:              "valid",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			secretData: map[string][]byte{
				ProviderSecretClientID:  []byte("client-id-1"),
				ProviderSecretClientKey: []byte("client-key-1"),
			},
			want: map[string]any{
				ProviderSecretClientID:  "client-id-1",
				ProviderSecretClientKey: "client-key-1",
			},
			wantErr: assert.NoError,
		},
		{
			name:              "secret-not-found",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			want:              nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if !assert.ErrorIs(t, err, errors.InvalidCredentialDataError) {
					return false
				}

				return assert.EqualError(t, err,
					fmt.Sprintf(`%s, secrets "foo" not found`,
						errors.InvalidCredentialDataError),
					i...)
			},
		},
		{
			name:              "invalid-no-data",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			secretData:        map[string][]byte{},
			want:              nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expectErr := errors.NewIncompleteCredentialError(
					ProviderSecretClientKey,
					ProviderSecretClientID,
				)
				return assert.EqualError(t, err, expectErr.Error(), i...)
			},
		},
		{
			name:              "invalid-empty-values",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			secretData: map[string][]byte{
				ProviderSecretClientID:  make([]byte, 0),
				ProviderSecretClientKey: make([]byte, 0),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expectErr := errors.NewIncompleteCredentialError(
					ProviderSecretClientKey,
					ProviderSecretClientID,
				)
				return assert.EqualError(t, err, expectErr.Error(), i...)
			},
		},
		{
			name:              "invalid-secret-client-key",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			secretData: map[string][]byte{
				ProviderSecretClientID: []byte("client-id-1"),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expectErr := errors.NewIncompleteCredentialError(
					ProviderSecretClientKey,
				)
				return assert.EqualError(t, err, expectErr.Error(), i...)
			},
		},
		{
			name:              "invalid-secret-client-id",
			authObj:           authObj,
			providerNamespace: "tenant-ns",
			secretData: map[string][]byte{
				ProviderSecretClientKey: []byte("client-key-1"),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				expectErr := errors.NewIncompleteCredentialError(
					ProviderSecretClientID,
				)
				return assert.EqualError(t, err, expectErr.Error(), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &ServicePrincipleCredentialProvider{
				authObj:           tt.authObj,
				providerNamespace: tt.providerNamespace,
			}

			client := fake.NewClientBuilder().Build()
			if tt.secretData != nil {
				require.NoError(t, client.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.authObj.Spec.ServicePrincipal.SecretRef,
						Namespace: tt.providerNamespace,
					},
					Data: tt.secretData,
				}))
			}
			got, err := l.GetCreds(ctx, client)
			if !tt.wantErr(t, err, fmt.Sprintf("GetCreds(%v, %v)", ctx, client)) {
				return
			}
			assert.Equalf(t, tt.want, got, "GetCreds(%v, %v)", ctx, client)
		})
	}
}
