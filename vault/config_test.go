// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/vault/api"
	vconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/hashicorp/vault-secrets-operator/consts"
)

func TestMakeVaultClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

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
		"vault timeout not nil": {
			vaultConfig: &ClientConfig{
				VaultNamespace: "vault-test-namespace",
				Timeout:        ptr.To[time.Duration](10 * time.Second),
			},
			CACert:        nil,
			expectedError: nil,
		},
		"headers": {
			vaultConfig: &ClientConfig{
				Headers: http.Header{
					"X-Proxy-Setting": []string{"yes"},
					"Y-Proxy-Setting": []string{"no"},
				},
				VaultNamespace: "vault-test-namespace",
			},
			CACert:        nil,
			expectedError: nil,
		},
		"headers can't override namespace": {
			vaultConfig: &ClientConfig{
				Headers: http.Header{
					"X-Proxy-Setting":           []string{"yes"},
					"Y-Proxy-Setting":           []string{"no"},
					vconsts.NamespaceHeaderName: []string{"nope"},
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
			vaultClient, err := MakeVaultClient(ctx, tc.vaultConfig, fakeClient)
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
					assert.Truef(t, tlsConfig.RootCAs.Equal(expectedCertPool),
						"expected CA cert pool %v, got %v", expectedCertPool, tlsConfig.RootCAs,
					)
				}

				expectedHeaders := makeVaultHttpHeaders(t, tc.vaultConfig.VaultNamespace, tc.vaultConfig.Headers)
				assert.Equalf(t, expectedHeaders, vaultClient.Headers(),
					"expected headers %v, got %v", expectedHeaders, vaultClient.Headers(),
				)

				var expectedTimeout time.Duration
				if tc.vaultConfig.Timeout != nil {
					expectedTimeout = *tc.vaultConfig.Timeout
				} else {
					expectedTimeout = api.DefaultConfig().Timeout
				}
				assert.Equalf(t, expectedTimeout, vaultConfig.Timeout,
					"expected timeout %v, got %v", expectedTimeout, vaultConfig.Timeout)
			}
		})
	}
}

func makeVaultHttpHeaders(t *testing.T, namespace string, headers http.Header) http.Header {
	t.Helper()

	h := make(http.Header)
	for k, values := range headers {
		for _, v := range values {
			h.Add(k, v)
		}
	}
	h.Set("X-Vault-Request", "true")
	if namespace != "" {
		h.Set(vconsts.NamespaceHeaderName, namespace)
	}

	return h
}

func TestClientConfig_MutuallyExclusiveCACerts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCABytes, err := generateCA()
	require.NoError(t, err)

	// Create a temporary CA cert file for testing
	tmpFile, err := os.CreateTemp("", "test-ca-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(testCABytes)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	tests := map[string]struct {
		vaultConfig   *ClientConfig
		CACert        []byte
		expectedError error
	}{
		"both CACertSecretRef and CACertPath set": {
			vaultConfig: &ClientConfig{
				CACertSecretRef: "vault-cert",
				CACertPath:      tmpFile.Name(),
				K8sNamespace:    "vault",
				Address:         "localhost",
			},
			CACert:        testCABytes,
			expectedError: fmt.Errorf("invalid CA cert config: CACertSecretRef and CACertPath are mutually exclusive, only one can be set"),
		},
		"only CACertPath set - success": {
			vaultConfig: &ClientConfig{
				CACertPath:    tmpFile.Name(),
				K8sNamespace:  "vault",
				Address:       "localhost",
				TLSServerName: "vault-server",
			},
			CACert:        nil,
			expectedError: nil,
		},
		"only CACertSecretRef set - success": {
			vaultConfig: &ClientConfig{
				CACertSecretRef: "vault-cert",
				K8sNamespace:    "vault",
				Address:         "localhost",
				TLSServerName:   "vault-server",
			},
			CACert:        testCABytes,
			expectedError: nil,
		},
		"CACertPath file does not exist": {
			vaultConfig: &ClientConfig{
				CACertPath:   "/nonexistent/ca.pem",
				K8sNamespace: "vault",
				Address:      "localhost",
			},
			CACert:        nil,
			expectedError: fmt.Errorf("failed to read CA cert file \"/nonexistent/ca.pem\": open /nonexistent/ca.pem: no such file or directory"),
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
				clientBuilder = clientBuilder.WithObjects(&caCertSecret)
			}
			fakeClient := clientBuilder.Build()
			vaultClient, err := MakeVaultClient(ctx, tc.vaultConfig, fakeClient)
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

				// Verify CA cert pool is set when CACertPath is used
				if tc.vaultConfig.CACertPath != "" {
					require.NotNil(t, tlsConfig.RootCAs)
					expectedCertPool, err := rootcerts.AppendCertificate(testCABytes)
					require.NoError(t, err)
					assert.Truef(t, tlsConfig.RootCAs.Equal(expectedCertPool),
						"expected CA cert pool %v, got %v", expectedCertPool, tlsConfig.RootCAs,
					)
				}
			}
		})
	}
}
