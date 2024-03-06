// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/go-rootcerts"
	vconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func TestMakeVaultClient(t *testing.T) {
	testCABytes, err := generateCA()
	require.NoError(t, err)

	tests := map[string]struct {
		vaultConfig     *ClientConfig
		CACert          []byte
		makeBlankSecret bool
		expectedError   error
	}{
		"empty everything": {
			vaultConfig:   nil,
			CACert:        nil,
			expectedError: fmt.Errorf("ClientConfig was nil"),
		},
		"caCertSecretRef but k8s secret doesn't exist": {
			vaultConfig: &ClientConfig{
				CACertSecretRef: "missing",
				K8sNamespace:    "default",
				Address:         "localhost",
			},
			CACert:        nil,
			expectedError: fmt.Errorf(`secrets "missing" not found`),
		},
		"caCert specified": {
			vaultConfig: &ClientConfig{
				CACertSecretRef: "vault-cert",
				K8sNamespace:    "vault",
				Address:         "localhost",
				TLSServerName:   "vault-server",
			},
			CACert:        testCABytes,
			expectedError: nil,
		},
		"caCert specified but empty": {
			vaultConfig: &ClientConfig{
				CACertSecretRef: "vault-cert",
				K8sNamespace:    "vault",
				Address:         "localhost",
				TLSServerName:   "vault-server",
			},
			CACert:          testCABytes,
			makeBlankSecret: true,
			expectedError:   fmt.Errorf(`%q not present in the CA secret "vault/vault-cert"`, consts.TLSSecretCAKey),
		},
		"vault namespace": {
			vaultConfig: &ClientConfig{
				VaultNamespace: "vault-test-namespace",
			},
			CACert:        nil,
			expectedError: nil,
		},
		"headers": {
			vaultConfig: &ClientConfig{
				Headers: map[string]string{
					"X-Proxy-Setting": "yes",
					"Y-Proxy-Setting": "no",
				},
				VaultNamespace: "vault-test-namespace",
			},
			CACert:        nil,
			expectedError: nil,
		},
		"headers can't override namespace": {
			vaultConfig: &ClientConfig{
				Headers: map[string]string{
					"X-Proxy-Setting":           "yes",
					"Y-Proxy-Setting":           "no",
					vconsts.NamespaceHeaderName: "nope",
				},
				VaultNamespace: "vault-test-namespace",
			},
			CACert:        nil,
			expectedError: fmt.Errorf(`setting header "X-Vault-Namespace" on VaultConnection is not permitted`),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clientBuilder := fake.NewClientBuilder()
			if len(tc.CACert) != 0 {
				caCertSecret := corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      tc.vaultConfig.CACertSecretRef,
						Namespace: tc.vaultConfig.K8sNamespace,
					},
					Data: map[string][]byte{consts.TLSSecretCAKey: tc.CACert},
				}
				if tc.makeBlankSecret {
					delete(caCertSecret.Data, consts.TLSSecretCAKey)
				}
				clientBuilder = clientBuilder.WithObjects(&caCertSecret)
			}
			fakeClient := clientBuilder.Build()
			vaultClient, err := MakeVaultClient(context.Background(), tc.vaultConfig, fakeClient)
			if tc.expectedError != nil {
				assert.EqualError(t, err, tc.expectedError.Error())
				assert.Nil(t, vaultClient)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, vaultClient)
				vaultClient.SetCloneHeaders(true)
				vaultConfig := vaultClient.CloneConfig()

				tlsConfig := vaultConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

				assert.Equal(t, tc.vaultConfig.Address, vaultConfig.Address)
				assert.Equal(t, tc.vaultConfig.SkipTLSVerify, tlsConfig.InsecureSkipVerify)
				assert.Equal(t, tc.vaultConfig.TLSServerName, tlsConfig.ServerName)

				assert.Equal(t, tc.vaultConfig.VaultNamespace,
					vaultClient.Headers().Get(vconsts.NamespaceHeaderName),
				)
				if len(tc.CACert) != 0 && tc.vaultConfig.CACertSecretRef != "" {
					require.NotNil(t, tlsConfig.RootCAs)
					expectedCertPool, err := rootcerts.AppendCertificate(testCABytes)
					require.NoError(t, err)
					assert.True(t, tlsConfig.RootCAs.Equal(expectedCertPool), "The CA cert in the client doesn't match the expected cert")
				}

				expectedHeaders := makeVaultHttpHeaders(t, tc.vaultConfig.VaultNamespace, tc.vaultConfig.Headers)
				assert.Equal(t, expectedHeaders, vaultClient.Headers(), "The headers in the client don't match the expected headers")
			}
		})
	}
}

func makeVaultHttpHeaders(t *testing.T, namespace string, headers map[string]string) http.Header {
	t.Helper()

	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	h.Set("X-Vault-Request", "true")
	if namespace != "" {
		h.Set(vconsts.NamespaceHeaderName, namespace)
	}

	return h
}
