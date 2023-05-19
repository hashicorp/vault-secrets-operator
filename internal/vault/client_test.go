// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault/credentials"
)

const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDVDCCAjwCCQDFiyFY1M6afTANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJV
UzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEgMB4GA1UE
CgwXVmF1bHQgVGVzdGluZyBBdXRob3JpdHkxFDASBgNVBAMMC2V4YW1wbGUubmV0
MB4XDTIwMDkxODAxMjkxM1oXDTQ1MDkxODAxMjkxM1owbDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoM
F1ZhdWx0IFRlc3RpbmcgQXV0aG9yaXR5MRQwEgYDVQQDDAtleGFtcGxlLm5ldDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALCA9oKv+ESRHX2e/iq1PlGr
zD23/MBS0V+fWQDY0hyEqY98CGwRtF6pEcLEYsreArj5/zznsIevLkNOD+beg43y
WpEJlCPgDhGXI/Oima6ooHVEIMaIKLjK7GrSzAb3rNRGACwrR/u/IKaFl+XJG0qx
g8mOZ3fByaAlIk+shVLUcIedNN1tNR+6/4ZpHg7PDjrZXP4XKrmKPTh4yqfu+BtZ
9IY2oyregqEsGW1/3h1NM+LHGVakTV2d/mwMYHhwoq9Y8BD+PemT5z8TmhH/cIk5
P8Q8ud5/q6YTIJg9TELKebLAeNtRNnNoHeUoRTjiW1MBwNHtgyTTY+H3W/9Dne0C
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEAXmygFkGIBnXxKlsTDiV8RW2iHLgFdZFJ
hcU8UpxZhhaL5JbQl6byfbHjrX31q7ii8uC8FcbW0AEdnEQAb9Ui6a+if7HwXNmI
DTlYl+lMlk9RtWvExw6AEEbg5nCpGaKexm7wJgzYGP9by9pQ7wX/CS7ofCzCK+Al
uSIqjPkMC201ZXH39n1lxxq6BacdYjv8wo4mMzi8iTSQGVWPdjHZVYOClFgN6hoj
8SkrrSe888a0H+i7EknRxC4sLRaMUK/FAvwtXaSZi2djruAtQzQGQ56m1phC2C/k
k9aL00AQ9Y4KTfiJD7LK8YIZDnFKLOCJhYgKCLCOVwOHb7836SNCxA==
-----END CERTIFICATE-----`

func Test_defaultClient_CheckExpiry(t *testing.T) {
	type fields struct {
		lastResp    *api.Secret
		lastRenewal int64
	}
	type args struct {
		offset int64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid-with-offset",
			fields: fields{
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 25,
			},
			args: args{
				offset: 4,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "valid-with-1s-lease-zero-offset",
			fields: fields{
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 1,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix(),
			},
			args: args{
				offset: 0,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "expired-with-offset",
			fields: fields{
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 25,
			},
			args: args{
				offset: 5,
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "expired-without-offset",
			fields: fields{
				lastResp: &api.Secret{
					Renewable: true,
					Auth: &api.SecretAuth{
						LeaseDuration: 30,
						Renewable:     true,
					},
				},
				lastRenewal: time.Now().Unix() - 30,
			},
			args: args{
				offset: 0,
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			fields: fields{},
			want:   false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return err != nil
			},
		},
		{
			name: "error-authSecret-nil",
			fields: fields{
				lastRenewal: time.Now().Unix(),
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
		{
			name: "error-lastRenewal-zero",
			fields: fields{
				lastRenewal: 0,
				lastResp:    &api.Secret{},
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
		{
			name: "error-lastRenewal-zero-and-lasResp-nil",
			fields: fields{
				lastRenewal: 0,
				lastResp:    nil,
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "cannot check client token expiry, never logged in", i...)
				return err != nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				authSecret:  tt.fields.lastResp,
				lastRenewal: tt.fields.lastRenewal,
			}
			got, err := c.CheckExpiry(tt.args.offset)
			if !tt.wantErr(t, err, fmt.Sprintf("CheckExpiry(%v)", tt.args.offset)) {
				return
			}
			assert.Equalf(t, tt.want, got, "CheckExpiry(%v)", tt.args.offset)
		})
	}
}

func Test_defaultClient_Init(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name              string
		client            ctrlclient.Client
		authObj           *secretsv1alpha1.VaultAuth
		connObj           *secretsv1alpha1.VaultConnection
		createNamespaces  bool
		createCASecret    bool
		caSecretData      map[string][]byte
		providerNamespace string
		opts              *ClientOptions
		wantErr           assert.ErrorAssertionFunc
	}{
		{
			name:             "valid-secret-ca-cert",
			createNamespaces: true,
			createCASecret:   true,
			caSecretData: map[string][]byte{
				"ca.crt": []byte(testCACertPEM),
			},
			client: fake.NewClientBuilder().Build(),
			authObj: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "default",
					Method:             credentials.ProviderMethodKubernetes,
					Mount:              "kubernetes",
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						ServiceAccount: "default",
					},
				},
			},
			connObj: &secretsv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultConnectionSpec{
					CACertSecretRef: "baz",
					SkipTLSVerify:   false,
				},
			},
			providerNamespace: "vso",
			wantErr:           assert.NoError,
		},
		{
			name:             "invalid-secret-missing-ca-cert",
			createNamespaces: true,
			createCASecret:   true,
			client:           fake.NewClientBuilder().Build(),
			authObj: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "default",
					Method:             credentials.ProviderMethodKubernetes,
					Mount:              "kubernetes",
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						ServiceAccount: "default",
					},
				},
			},
			connObj: &secretsv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultConnectionSpec{
					CACertSecretRef: "baz",
				},
			},
			providerNamespace: "vso",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					`"ca.crt" not present in the CA secret "%s/%s"`, "vso", "baz"), i...)
			},
		},
		{
			name:             "invalid-empty-ca-cert",
			createNamespaces: true,
			createCASecret:   true,
			caSecretData: map[string][]byte{
				"ca.crt": {},
			},
			client: fake.NewClientBuilder().Build(),
			authObj: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "default",
					Method:             credentials.ProviderMethodKubernetes,
					Mount:              "kubernetes",
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						ServiceAccount: "default",
					},
				},
			},
			connObj: &secretsv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultConnectionSpec{
					CACertSecretRef: "baz",
					SkipTLSVerify:   false,
				},
			},
			providerNamespace: "vso",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					`no valid certificates found for key "ca.crt" in CA secret "%s/%s"`, "vso", "baz"))
			},
		},
		{
			name:             "valid-empty-ca-cert-skip-tls-verify",
			createNamespaces: true,
			createCASecret:   true,
			caSecretData: map[string][]byte{
				"ca.crt": {},
			},
			client: fake.NewClientBuilder().Build(),
			authObj: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "default",
					Method:             credentials.ProviderMethodKubernetes,
					Mount:              "kubernetes",
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						ServiceAccount: "default",
					},
				},
			},
			connObj: &secretsv1alpha1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "vso",
				},
				Spec: secretsv1alpha1.VaultConnectionSpec{
					CACertSecretRef: "baz",
					SkipTLSVerify:   true,
				},
			},
			providerNamespace: "vso",
			wantErr:           assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.createNamespaces {
				ns := &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: tt.connObj.Namespace,
					},
				}

				require.NoError(t, tt.client.Create(ctx, ns))

				if tt.authObj.Spec.Kubernetes.ServiceAccount != "" {
					sa := &corev1.ServiceAccount{
						ObjectMeta: metav1.ObjectMeta{
							Name:      tt.authObj.Spec.Kubernetes.ServiceAccount,
							Namespace: tt.authObj.Namespace,
						},
					}

					require.NoError(t, tt.client.Create(ctx, sa))
				}

				if tt.createCASecret {
					secret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: tt.connObj.Namespace,
							Name:      tt.connObj.Spec.CACertSecretRef,
						},
						Data: tt.caSecretData,
						Type: "kubernetes.io/tls",
					}

					require.NoError(t, tt.client.Create(ctx, secret))
				}

				c := &defaultClient{}

				err := c.Init(ctx, tt.client, tt.authObj, tt.connObj, tt.providerNamespace, tt.opts)
				tt.wantErr(t, err,
					fmt.Sprintf("Init(%v, %v, %v, %v, %v, %v)",
						ctx, tt.client, tt.authObj, tt.connObj, tt.providerNamespace, tt.opts))

				opts := tt.opts
				if opts == nil {
					opts = defaultClientOptions()
				}
				assert.Equal(t, opts.SkipRenewal, c.skipRenewal)

				if err != nil {
					assert.Nil(t, c.authObj)
					assert.Nil(t, c.connObj)
					return
				}

				assert.Equal(t, tt.connObj, c.connObj)
				assert.Equal(t, tt.authObj, c.authObj)

				if assert.NotNil(t, c.client, "vault client not set from Init()") {
					return
				}

				actualPool := c.client.CloneConfig().TLSConfig().RootCAs
				expectedPool := getTestCertPool(t, tt.caSecretData["ca.crt"])
				assert.True(t, expectedPool.Equal(actualPool))
			}
		})
	}
}

func getTestCertPool(t *testing.T, cert []byte) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(cert); !ok {
		assert.Fail(t, "test certificate contains no valid certificates")
	}
	return pool
}
