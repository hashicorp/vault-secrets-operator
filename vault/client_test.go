// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault"
	vaultcredsconsts "github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"
)

func Test_defaultClient_CheckExpiry(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	ctx := context.Background()

	ca, err := generateCA()
	require.NoError(t, err)

	defaultAuthObj := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: "vso",
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: consts.NameDefault,
			Method:             vaultcredsconsts.ProviderMethodKubernetes,
			Mount:              "kubernetes",
			Namespace:          "baz-ns",
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           "vso-role",
				ServiceAccount: consts.NameDefault,
			},
		},
	}

	defaultConnObj := &secretsv1beta1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: "vso",
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			CACertSecretRef: "baz",
			SkipTLSVerify:   false,
		},
	}

	connObjSkipTLSVerify := &secretsv1beta1.VaultConnection{
		ObjectMeta: defaultConnObj.ObjectMeta,
		Spec: secretsv1beta1.VaultConnectionSpec{
			CACertSecretRef: "baz",
			SkipTLSVerify:   true,
		},
	}

	tests := []struct {
		name                  string
		client                ctrlclient.Client
		authObj               *secretsv1beta1.VaultAuth
		connObj               *secretsv1beta1.VaultConnection
		withoutCASecret       bool
		withoutServiceAccount bool
		caSecretData          map[string][]byte
		providerNamespace     string
		opts                  *ClientOptions
		wantErr               assert.ErrorAssertionFunc
	}{
		{
			name: "valid-secret-ca-cert",
			caSecretData: map[string][]byte{
				consts.TLSSecretCAKey: ca,
			},
			client:            fake.NewClientBuilder().Build(),
			authObj:           defaultAuthObj,
			connObj:           defaultConnObj,
			providerNamespace: defaultConnObj.Namespace,
			wantErr:           assert.NoError,
		},
		{
			name: "valid-secret-ca-cert-other-provider-ns",
			caSecretData: map[string][]byte{
				consts.TLSSecretCAKey: ca,
			},
			client:            fake.NewClientBuilder().Build(),
			authObj:           defaultAuthObj,
			connObj:           defaultConnObj,
			providerNamespace: "vso-provider-ns",
			wantErr:           assert.NoError,
		},
		{
			name:    "error-secret-missing-ca-cert",
			client:  fake.NewClientBuilder().Build(),
			authObj: defaultAuthObj,
			connObj: defaultConnObj,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					`%q not present in the CA secret "%s/%s"`, consts.TLSSecretCAKey, "vso", "baz"), i...)
			},
		},
		{
			name: "valid-empty-ca-cert-without-tls-verify",
			caSecretData: map[string][]byte{
				consts.TLSSecretCAKey: {},
			},
			client:            fake.NewClientBuilder().Build(),
			authObj:           defaultAuthObj,
			connObj:           connObjSkipTLSVerify,
			providerNamespace: "provider-vso",
			wantErr:           assert.NoError,
		},
		{
			name: "invalid-empty-ca-cert-with-tls-verify",
			caSecretData: map[string][]byte{
				consts.TLSSecretCAKey: {},
			},
			client:  fake.NewClientBuilder().Build(),
			authObj: defaultAuthObj,
			connObj: defaultConnObj,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					`no valid certificates found for key %q in CA secret "%s/%s"`, consts.TLSSecretCAKey, "vso", "baz"))
			},
		},
		{
			name:                  "invalid-service-account-not-found",
			withoutServiceAccount: true,
			caSecretData: map[string][]byte{
				consts.TLSSecretCAKey: {},
			},
			client:  fake.NewClientBuilder().Build(),
			authObj: defaultAuthObj,
			connObj: connObjSkipTLSVerify,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					"serviceaccounts %q not found", consts.NameDefault))
			},
		},
		{
			name:            "invalid-missing-secret",
			withoutCASecret: true,
			authObj:         defaultAuthObj,
			connObj:         defaultConnObj,
			client:          fake.NewClientBuilder().Build(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					`secrets %q not found`, "baz"))
			},
		},
		{
			name:            "invalid-nil-VaultConnection",
			authObj:         defaultAuthObj,
			connObj:         nil,
			client:          fake.NewClientBuilder().Build(),
			withoutCASecret: true,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "VaultConnection was nil")
			},
		},
		{
			name:                  "invalid-nil-VaultAuth",
			authObj:               nil,
			connObj:               defaultConnObj,
			withoutServiceAccount: true,
			client:                fake.NewClientBuilder().Build(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "VaultAuth was nil")
			},
		},
		{
			name:                  "invalid-nil-ctrl-client",
			withoutCASecret:       true,
			withoutServiceAccount: true,
			authObj:               defaultAuthObj,
			connObj:               defaultConnObj,
			client:                nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "ctrl-runtime Client was nil")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.withoutCASecret {
				require.NotNil(t, tt.client)
				require.NotNil(t, tt.connObj)

				require.NoError(t, tt.client.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: tt.connObj.Namespace,
						Name:      tt.connObj.Spec.CACertSecretRef,
					},
					Data: tt.caSecretData,
					Type: "kubernetes.io/tls",
				}))
			}

			if !tt.withoutServiceAccount {
				require.NotNil(t, tt.client)
				require.NotNil(t, tt.authObj)

				ns := tt.authObj.Namespace
				if tt.providerNamespace != "" {
					ns = tt.providerNamespace
				}
				require.NoError(t, tt.client.Create(ctx, &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.authObj.Spec.Kubernetes.ServiceAccount,
						Namespace: ns,
					},
				}))
			}

			c := &defaultClient{}

			err := c.Init(ctx, tt.client, tt.authObj, tt.connObj, tt.providerNamespace, tt.opts)
			if !tt.wantErr(t, err,
				fmt.Sprintf("Init(%v, %v, %v, %v, %v, %v)",
					ctx, tt.client, tt.authObj, tt.connObj, tt.providerNamespace, tt.opts)) {
				return
			}

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

			assert.Equalf(t, c.Namespace(), tt.authObj.Spec.Namespace,
				"expected namespace %q, got %q", tt.authObj.Spec.Namespace, c.Namespace())

			if assert.NotNil(t, c.client, "vault client not set from Init()") {
				return
			}

			actualPool := c.client.CloneConfig().TLSConfig().RootCAs
			expectedPool := getTestCertPool(t, tt.caSecretData[consts.TLSSecretCAKey])
			assert.True(t, expectedPool.Equal(actualPool))
		})
	}
}

func Test_defaultClient_Validate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name           string
		c              *api.Client
		handler        *testHandler
		authSecret     *api.Secret
		skipRenewal    bool
		lastRenewal    int64
		watcher        *api.LifetimeWatcher
		tainted        bool
		lastWatcherErr error
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name: "invalid-expired",
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 5,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			watcher:        &api.LifetimeWatcher{},
			lastWatcherErr: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "client token expired", i...)
			},
		},
		{
			name: "invalid-with-auth-secret-nil",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"auth secret not set, never logged in", i...)
			},
		},
		{
			name:       "invalid-with-secret-auth-nil",
			authSecret: &api.Secret{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"invalid auth secret, Auth field is nil", i...)
			},
		},
		{
			name: "valid-with-watcher",
			c:    &api.Client{},
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			watcher:        &api.LifetimeWatcher{},
			lastWatcherErr: nil,
			wantErr:        assert.NoError,
		},
		{
			name: "valid-with-watcher-skipRenewal",
			c:    &api.Client{},
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
				},
			},
			skipRenewal:    true,
			lastRenewal:    time.Now().Unix() - 5,
			watcher:        nil,
			lastWatcherErr: nil,
			wantErr:        assert.NoError,
		},
		{
			name: "valid-with-watcher-error-skipRenewal",
			c:    &api.Client{},
			authSecret: &api.Secret{
				LeaseDuration: 30,
				Renewable:     false,
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
				},
			},
			skipRenewal:    true,
			lastRenewal:    time.Now().Unix() - 5,
			lastWatcherErr: fmt.Errorf("lifetime watcher error"),
			wantErr:        assert.NoError,
		},
		{
			name: "valid-with-watcher-nil-non-renewable",
			c:    &api.Client{},
			authSecret: &api.Secret{
				LeaseDuration: 30,
				Renewable:     false,
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
					Renewable:     false,
				},
			},
			skipRenewal: false,
			lastRenewal: time.Now().Unix() - 5,
			wantErr:     assert.NoError,
		},
		{
			name: "invalid-with-watcher-nil",
			authSecret: &api.Secret{
				LeaseDuration: 30,
				Renewable:     false,
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
					Renewable:     true,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			lastWatcherErr: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "lifetime watcher not set", i...)
			},
		},
		{
			name: "invalid-with-watcher-error",
			authSecret: &api.Secret{
				LeaseDuration: 30,
				Renewable:     false,
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
					Renewable:     true,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			lastWatcherErr: fmt.Errorf("lifetime watcher error"),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "lifetime watcher error", i...)
			},
		},
		{
			name: "invalid-client-not-set",
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			watcher:        &api.LifetimeWatcher{},
			lastWatcherErr: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "client not set", i...)
			},
		},
		{
			name: "invalid-tainted-client",
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					LeaseDuration: 30,
				},
			},
			skipRenewal:    false,
			lastRenewal:    time.Now().Unix() - 5,
			watcher:        &api.LifetimeWatcher{},
			lastWatcherErr: nil,
			tainted:        true,
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.ErrorContains(t, err,
					"tainted client is invalid",
					i...,
				) {
					return assert.True(t, IsForbiddenError(err), i...)
				}
				return false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.c != nil && tt.handler != nil {
				require.Fail(t, "cannot set both client and handler")
			}

			if tt.c == nil && tt.handler != nil {
				config, l := NewTestHTTPServer(t, tt.handler.handler())
				t.Cleanup(func() {
					l.Close()
				})

				client, err := api.NewClient(config)
				require.NoError(t, err)
				tt.c = client
			}

			c := &defaultClient{
				client:         tt.c,
				authSecret:     tt.authSecret,
				skipRenewal:    tt.skipRenewal,
				lastRenewal:    tt.lastRenewal,
				watcher:        tt.watcher,
				tainted:        tt.tainted,
				lastWatcherErr: tt.lastWatcherErr,
			}
			tt.wantErr(t, c.Validate(ctx), "Validate()")
		})
	}
}

func Test_defaultClient_Read(t *testing.T) {
	t.Parallel()

	handlerFunc := func(t *testHandler, w http.ResponseWriter, req *http.Request) {
		m, err := json.Marshal(
			&api.Secret{
				Data: map[string]interface{}{
					"foo": "bar",
				},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(m)
	}

	ctx := context.Background()
	tests := []struct {
		name           string
		request        ReadRequest
		handler        *testHandler
		expectRequests int
		expectPaths    []string
		expectParams   []map[string]interface{}
		expectValues   []url.Values
		want           Response
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name:    "default-request",
			request: NewReadRequest("foo/bar", nil),
			handler: &testHandler{
				handlerFunc: handlerFunc,
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/foo/bar"},
			want: &defaultResponse{
				secret: &api.Secret{
					Data: map[string]interface{}{
						"foo": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "fail-default-nil-response",
			request: NewReadRequest("foo/bar", nil),
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/foo/bar"},
			want:           nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf(`empty response from Vault, path="foo/bar"`))
			},
		},
		{
			name:    "kv-v1-request",
			request: NewKVReadRequestV1("kv-v1", "secrets"),
			handler: &testHandler{
				handlerFunc: handlerFunc,
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/kv-v1/secrets"},
			want: &kvV1Response{
				secret: &api.Secret{
					Data: map[string]interface{}{
						"foo": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "kv-v2-request",
			request: NewKVReadRequestV2("kv-v2", "secrets", 0),
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					m, err := json.Marshal(
						&api.Secret{
							Data: map[string]interface{}{
								"data": map[string]interface{}{
									"foo": "bar",
								},
							},
						},
					)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					w.WriteHeader(http.StatusOK)
					w.Write(m)
				},
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/kv-v2/data/secrets"},
			want: &kvV2Response{
				secret: &api.Secret{
					Data: map[string]interface{}{
						"data": map[string]interface{}{
							"foo": "bar",
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "kv-v2-request-with-version",
			request: NewKVReadRequestV2("kv-v2", "secrets", 1),
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					m, err := json.Marshal(
						&api.Secret{
							Data: map[string]interface{}{
								"data": map[string]interface{}{
									"foo": "bar",
								},
							},
						},
					)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					w.WriteHeader(http.StatusOK)
					w.Write(m)
				},
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/kv-v2/data/secrets"},
			expectValues: []url.Values{
				{
					"version": []string{"1"},
				},
			},
			want: &kvV2Response{
				secret: &api.Secret{
					Data: map[string]interface{}{
						"data": map[string]interface{}{
							"foo": "bar",
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "fail-kv-v1-nil-response",
			request: NewKVReadRequestV1("kv-v1", "secrets"),
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/kv-v1/secrets"},
			want:           nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf(`empty response from Vault, path="kv-v1/secrets"`))
			},
		},
		{
			name:    "fail-kv-v2-nil-response",
			request: NewKVReadRequestV2("kv-v2", "secrets", 0),
			handler: &testHandler{
				handlerFunc: func(t *testHandler, w http.ResponseWriter, req *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			},
			expectRequests: 1,
			expectPaths:    []string{"/v1/kv-v2/data/secrets"},
			want:           nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					fmt.Sprintf(`empty response from Vault, path="kv-v2/data/secrets"`))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, l := NewTestHTTPServer(t, tt.handler.handler())
			t.Cleanup(func() {
				l.Close()
			})

			client, err := api.NewClient(config)
			require.NoError(t, err)

			c := &defaultClient{
				client: client,
				// needed for Client Prometheus metrics
				connObj: &secretsv1beta1.VaultConnection{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "bar",
					},
				},
			}
			got, err := c.Read(ctx, tt.request)
			if !tt.wantErr(t, err, fmt.Sprintf("ReadKV(%v, %v)", ctx, tt.request)) {
				return
			}
			assert.Equalf(t, tt.want, got, "ReadKV(%v, %v)", ctx, tt.request)
			assert.Equal(t, tt.expectRequests, tt.handler.requestCount)
			assert.Equal(t, tt.expectPaths, tt.handler.paths)
			assert.Equal(t, tt.expectParams, tt.handler.params)
			assert.Equal(t, tt.expectValues, tt.handler.values)
		})
	}
}

func Test_defaultClient_Close(t *testing.T) {
	t.Parallel()

	handlerFunc := func(t *testHandler, w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusOK)
	}

	tests := []struct {
		name           string
		revoke         bool
		expectRequests int
		expectParams   []map[string]interface{}
		expectPaths    []string
	}{
		{
			name:   "ensure-closed",
			revoke: false,
		},
		{
			name:           "ensure-closed-with-revoke",
			revoke:         true,
			expectPaths:    []string{"/v1/auth/token/revoke-self"},
			expectRequests: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &testHandler{
				handlerFunc: handlerFunc,
			}
			config, l := NewTestHTTPServer(t, h.handler())
			t.Cleanup(func() {
				l.Close()
			})

			client, err := api.NewClient(config)
			require.NoError(t, err)

			c := &defaultClient{
				client: client,
			}

			c.Close(tt.revoke)

			assert.Equal(t, tt.expectPaths, h.paths)
			assert.Equal(t, tt.expectParams, h.params)
			assert.Equal(t, tt.expectRequests, h.requestCount)

			assert.True(t, c.closed)
			assert.NotNil(t, c.client)
		})
	}
}

func Test_defaultClient_hashAccessor(t *testing.T) {
	t.Parallel()

	accessor := "3cb18a45-eb9e-0ed8-149b-ae4f83808925"
	want := fmt.Sprintf("%x", blake2b.Sum256([]byte(accessor)))
	tests := []struct {
		name       string
		authSecret *api.Secret
		want       string
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					Accessor: accessor,
				},
			},
			want:    want,
			wantErr: assert.NoError,
		},
		{
			name:    "nil-authSecret",
			want:    "",
			wantErr: assert.NoError,
		},
		{
			name:       "nil-authSecret-auth",
			authSecret: &api.Secret{},
			wantErr:    assert.NoError,
		},
		{
			name: "invalid-accessor-format",
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{},
				Data: map[string]interface{}{
					"accessor": 1,
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "token found but in the wrong format", i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				authSecret: tt.authSecret,
				id:         want,
			}

			got, err := c.hashAccessor()
			if !tt.wantErr(t, err, fmt.Sprintf("hashAccessor()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "hashAccessor()")
		})
	}
}

func Test_defaultClient_Taint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "taint",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{}
			c.Taint()
			assert.True(t, c.tainted)
		})
	}
}

func Test_defaultClient_Tainted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tainted    bool
		assertFunc assert.BoolAssertionFunc
	}{
		{
			name:       "tainted",
			tainted:    true,
			assertFunc: assert.True,
		},
		{
			name:       "not-tainted",
			tainted:    false,
			assertFunc: assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				tainted: tt.tainted,
			}

			got := c.Tainted()
			tt.assertFunc(t, got, "Tainted()")
		})
	}
}

func Test_defaultClient_Untaint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tainted    bool
		assertFunc assert.BoolAssertionFunc
	}{
		{
			name:       "tainted",
			tainted:    true,
			assertFunc: assert.True,
		},
		{
			name:       "not-tainted",
			tainted:    false,
			assertFunc: assert.False,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				tainted: tt.tainted,
			}

			got := c.Untaint()
			tt.assertFunc(t, got, "Untaint()")
		})
	}
}

func Test_defaultClient_Clone(t *testing.T) {
	t.Parallel()

	vc, err := api.NewClient(&api.Config{})
	require.NoError(t, err)

	vcc, err := vc.Clone()
	vcc.SetNamespace("baz")
	require.NoError(t, err)

	authObj := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: "vso",
		},
	}
	connObj := &secretsv1beta1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: "vso",
		},
	}
	authSecret := &api.Secret{
		Auth: &api.SecretAuth{
			Accessor: "accessor",
		},
	}

	credsProvider := &vault.KubernetesCredentialProvider{}
	tests := []struct {
		name               string
		client             *api.Client
		isClone            bool
		authObj            *secretsv1beta1.VaultAuth
		connObj            *secretsv1beta1.VaultConnection
		credentialProvider provider.CredentialProviderBase
		namespace          string
		authSecret         *api.Secret
		skipRenewal        bool
		lastRenewal        int64
		targetNamespace    string
		id                 string
		want               Client
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name:               "valid-clone",
			client:             vc,
			id:                 "foo",
			authObj:            authObj,
			connObj:            connObj,
			credentialProvider: credsProvider,
			targetNamespace:    "k8s",
			authSecret:         authSecret,
			want: &defaultClient{
				client:             vcc,
				id:                 "foo",
				isClone:            true,
				skipRenewal:        true,
				authObj:            authObj,
				connObj:            connObj,
				credentialProvider: credsProvider,
				targetNamespace:    "k8s",
				authSecret:         authSecret,
			},
			namespace: "baz",
			wantErr:   assert.NoError,
		},
		{
			name:      "invalid-clone-a-clone",
			namespace: "baz",
			isClone:   true,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "cannot clone a clone")
			},
		},
		{
			name: "invalid-empty-namespace",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "namespace cannot be empty")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				client:             tt.client,
				isClone:            tt.isClone,
				authObj:            tt.authObj,
				connObj:            tt.connObj,
				authSecret:         tt.authSecret,
				credentialProvider: tt.credentialProvider,
				skipRenewal:        tt.skipRenewal,
				lastRenewal:        tt.lastRenewal,
				targetNamespace:    tt.targetNamespace,
				id:                 tt.id,
			}
			got, err := c.Clone(tt.namespace)
			if !tt.wantErr(t, err, fmt.Sprintf("Clone(%v)", tt.namespace)) {
				return
			}

			assert.Equalf(t, tt.want, got, "Clone(%v)", tt.namespace)
		})
	}
}

func TestNewClientConfigFromConnObj(t *testing.T) {
	t.Parallel()
	connObjBase := &secretsv1beta1.VaultConnection{
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address:         "https://vault.example.com",
			Headers:         map[string]string{"foo": "bar"},
			TLSServerName:   "baz.biff",
			CACertSecretRef: "ca.crt",
			SkipTLSVerify:   true,
			Timeout:         "10s",
		},
	}

	connObjEmptyTimeout := connObjBase.DeepCopy()
	connObjEmptyTimeout.Spec.Timeout = ""

	tests := []struct {
		name    string
		connObj *secretsv1beta1.VaultConnection
		vaultNS string
		want    *ClientConfig
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "all-fields",
			connObj: connObjBase,
			want: &ClientConfig{
				Address:         "https://vault.example.com",
				Headers:         map[string]string{"foo": "bar"},
				TLSServerName:   "baz.biff",
				CACertSecretRef: "ca.crt",
				SkipTLSVerify:   true,
				Timeout:         ptr.To[time.Duration](10 * time.Second),
			},
			wantErr: assert.NoError,
		},
		{
			name:    "empty-timeout",
			connObj: connObjEmptyTimeout,
			want: &ClientConfig{
				Address:         "https://vault.example.com",
				Headers:         map[string]string{"foo": "bar"},
				TLSServerName:   "baz.biff",
				CACertSecretRef: "ca.crt",
				SkipTLSVerify:   true,
			},
			wantErr: assert.NoError,
		},
		{
			name:    "nil-connObj",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewClientConfigFromConnObj(tt.connObj, tt.vaultNS)
			if !tt.wantErr(t, err, fmt.Sprintf("NewClientConfigFromConnObj(%v, %v)", tt.connObj, tt.vaultNS)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"NewClientConfigFromConnObj(%v, %v)", tt.connObj, tt.vaultNS)
		})
	}
}

func Test_defaultClient_Renewable(t *testing.T) {
	tests := []struct {
		name       string
		authSecret *api.Secret
		want       bool
	}{
		{
			name: "auth-secret-unset",
			want: false,
		},
		{
			name: "renewable",
			want: true,
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					Renewable: true,
				},
			},
		},
		{
			name: "non-renewable",
			want: false,
			authSecret: &api.Secret{
				Auth: &api.SecretAuth{
					Renewable: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultClient{
				authSecret: tt.authSecret,
			}
			assert.Equalf(t, tt.want, c.Renewable(), "Renewable()")
		})
	}
}
