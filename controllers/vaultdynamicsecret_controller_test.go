// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	vsoconsts "github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

func Test_computeRelativeHorizon(t *testing.T) {
	tests := map[string]struct {
		vds              *secretsv1beta1.VaultDynamicSecret
		expectedInWindow bool
		expectedHorizon  time.Duration
	}{
		"full lease elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 600,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Until(time.Unix(nowFunc().Unix()-600, 0).Add(
				computeStartRenewingAt(time.Second*600, 67))),
		},
		"two thirds elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 450,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(nowFunc().Unix()-450, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(nowFunc()),
		},
		"one third elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 200,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(nowFunc().Unix()-200, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(nowFunc()),
		},
		"past end of lease": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 800,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(nowFunc().Unix()-800, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(nowFunc()),
		},
		"renewalPercent is 0": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 0,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(nowFunc().Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, 0)).Sub(nowFunc()),
		},
		"renewalPercent is cap": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: renewalPercentCap,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(nowFunc().Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, renewalPercentCap)).Sub(nowFunc()),
		},
		"renewalPercent exceeds cap": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: nowFunc().Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: renewalPercentCap + 1,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(nowFunc().Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, renewalPercentCap+1)).Sub(nowFunc()),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			actualHorizon, actualInWindow := computeRelativeHorizon(tt.vds)
			assert.Equal(t, math.Floor(tt.expectedHorizon.Seconds()),
				math.Floor(actualHorizon.Seconds()),
			)
			assert.Equal(t, tt.expectedInWindow, actualInWindow)
		})
	}
}

func TestVaultDynamicSecretReconciler_syncSecret(t *testing.T) {
	type fields struct {
		Client        client.Client
		runtimePodUID types.UID
	}
	type args struct {
		ctx     context.Context
		vClient *vault.MockRecordingVaultClient
		o       *secretsv1beta1.VaultDynamicSecret
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           *secretsv1beta1.VaultSecretLease
		expectRequests []*vault.MockRequest
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name: "without-params",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:  "baz",
						Path:   "foo",
						Params: nil,
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodGet,
					Path:   "baz/foo",
					Params: nil,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-params",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount: "baz",
						Path:  "foo",
						Params: map[string]string{
							"qux": "bar",
						},
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: map[string]any{
						"qux": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-method-put-and-params",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodPut,
						Params: map[string]string{
							"qux": "bar",
						},
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: map[string]any{
						"qux": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-method-post-and-params",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodPost,
						Params: map[string]string{
							"qux": "bar",
						},
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					// the vault client API always translates POST to PUT
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: map[string]any{
						"qux": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-method-get-and-params",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodGet,
						Params: map[string]string{
							"qux": "bar",
						},
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: map[string]any{
						"qux": "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "without-params-and-method-get",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodGet,
						Params:            nil,
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodGet,
					Path:   "baz/foo",
					Params: nil,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "without-params-and-method-put",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodPut,
						Params:            nil,
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: nil,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "without-params-and-method-post",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodPost,
						Params:            nil,
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want: &secretsv1beta1.VaultSecretLease{
				LeaseDuration: 0,
				Renewable:     false,
			},
			expectRequests: []*vault.MockRequest{
				{
					// the vault client API always translates POST to PUT
					Method: http.MethodPut,
					Path:   "baz/foo",
					Params: nil,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-unsupported-method",
			fields: fields{
				Client:        fake.NewClientBuilder().Build(),
				runtimePodUID: "",
			},
			args: args{
				ctx:     nil,
				vClient: &vault.MockRecordingVaultClient{},
				o: &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "baz",
						Namespace: "default",
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Mount:             "baz",
						Path:              "foo",
						RequestHTTPMethod: http.MethodOptions,
						Params:            nil,
						Destination: secretsv1beta1.Destination{
							Name:   "baz",
							Create: true,
						},
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{},
				},
			},
			want:           nil,
			expectRequests: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf(
					"unsupported HTTP method %q for sync", http.MethodOptions), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &VaultDynamicSecretReconciler{
				Client: tt.fields.Client,
			}
			got, _, err := r.syncSecret(tt.args.ctx, tt.args.vClient, tt.args.o, nil)
			if !tt.wantErr(t, err, fmt.Sprintf("syncSecret(%v, %v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o, nil)) {
				return
			}
			assert.Equalf(t, tt.want, got, "syncSecret(%v, %v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o, nil)
			assert.Equalf(t, tt.expectRequests, tt.args.vClient.Requests, "syncSecret(%v, %v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o, nil)
		})
	}
}

type reconcileTestClientFactory struct {
	client vault.Client
}

func (f *reconcileTestClientFactory) Get(context.Context, client.Client, client.Object) (vault.Client, error) {
	return f.client, nil
}

func (f *reconcileTestClientFactory) RegisterClientCallbackHandler(vault.ClientCallbackHandler) {}

// reconcileTestVaultClient wraps MockRecordingVaultClient with a cacheKey and
// satisfies the full vault.Client interface via a nil vault.Client embedding.
// MockRecordingVaultClient is a named field (not embedded) to avoid Go's
// method ambiguity with the embedded vault.Client interface.
type reconcileTestVaultClient struct {
	vault.Client
	MockRecordingVaultClient *vault.MockRecordingVaultClient
	cacheKey                 vault.ClientCacheKey
}

func (c *reconcileTestVaultClient) Read(ctx context.Context, r vault.ReadRequest) (vault.Response, error) {
	return c.MockRecordingVaultClient.Read(ctx, r)
}

func (c *reconcileTestVaultClient) Write(ctx context.Context, r vault.WriteRequest) (vault.Response, error) {
	return c.MockRecordingVaultClient.Write(ctx, r)
}

func (c *reconcileTestVaultClient) ID() string {
	return c.MockRecordingVaultClient.ID()
}

func (c *reconcileTestVaultClient) Taint() {
	c.MockRecordingVaultClient.Taint()
}

func (c *reconcileTestVaultClient) GetCacheKey() (vault.ClientCacheKey, error) {
	return c.cacheKey, nil
}

// staticCredsFixture holds the common test objects for the stale-TTL regression
// tests (syncSecret and Reconcile). It pre-computes the HMAC so both tests
// share identical setup.
type staticCredsFixture struct {
	secretData    map[string][]byte
	freshResponse *vaultResponse
	hmacKeySecret *corev1.Secret
	validator     helpers.HMACValidator
	secretMAC     string // base64-encoded
}

func newStaticCredsFixture(t *testing.T) *staticCredsFixture {
	t.Helper()

	secretData := map[string][]byte{
		"username": []byte("db-user"),
		"password": []byte("db-pass"),
	}

	hmacKey := []byte("0123456789abcdef") // 16 bytes
	hmacObjKey := client.ObjectKey{Namespace: "default", Name: "hmac-key"}
	hmacKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      hmacObjKey.Name,
			Namespace: hmacObjKey.Namespace,
		},
		Data: map[string][]byte{
			helpers.HMACKeyName: hmacKey,
		},
	}
	validator := helpers.NewHMACValidator(hmacObjKey)

	filteredData, err := helpers.FilterData(staticTransOpt, secretData)
	require.NoError(t, err)
	message, err := json.Marshal(filteredData)
	require.NoError(t, err)
	messageMAC, err := helpers.MACMessage(hmacKey, message)
	require.NoError(t, err)

	return &staticCredsFixture{
		secretData: secretData,
		freshResponse: &vaultResponse{
			secret: &api.Secret{},
			data: map[string]any{
				"last_vault_rotation": "2026-04-21T12:00:00Z",
				"rotation_period":     600,
				"ttl":                 540,
				"username":            "db-user",
				"password":            "db-pass",
			},
			k8s: secretData,
		},
		hmacKeySecret: hmacKeySecret,
		validator:     validator,
		secretMAC:     base64.StdEncoding.EncodeToString(messageMAC),
	}
}

// Regression test: on ForceSync (VaultAuth token expiry), syncSecret must
// refresh StaticCredsMetaData.TTL even when the HMAC matches (no rotation).
// Exercises syncSecret in isolation.
//
// Status before: TTL=600  |  Vault response: TTL=540 (same LastVaultRotation)
func TestVaultDynamicSecretReconciler_syncSecret_staticCredsRefreshesStatusOnMatchingHMAC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newStaticCredsFixture(t)

	vClient := &vault.MockRecordingVaultClient{
		ReadResponses: map[string][]vault.Response{
			// Two reads: initial doVault + one inside the awaitVaultSecretRotation
			// backoff loop (triggered because inLastSyncRotation=true).
			"database/static-creds/app": {f.freshResponse, f.freshResponse},
		},
	}

	secretClient := testutils.NewFakeClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
		},
		Data: f.secretData,
	}, f.hmacKeySecret).Build()

	obj := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount:            "database",
			Path:             "static-creds/app",
			AllowStaticCreds: true,
			Destination: secretsv1beta1.Destination{
				Name:   "app",
				Create: true,
			},
		},
		Status: secretsv1beta1.VaultDynamicSecretStatus{
			SecretMAC: f.secretMAC,
			StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(),
				RotationPeriod:    600,
				TTL:               600,
			},
		},
	}

	r := &VaultDynamicSecretReconciler{
		Client:        secretClient,
		SecretsClient: secretClient,
		HMACValidator: f.validator,
	}

	lease, updated, err := r.syncSecret(ctx, vClient, obj, nil)
	require.NoError(t, err)
	assert.False(t, updated)
	assert.Equal(t, f.secretMAC, obj.Status.SecretMAC)
	assert.Equal(t, &secretsv1beta1.VaultSecretLease{
		LeaseDuration: 0,
		Renewable:     false,
	}, lease)
	assert.Equal(t, int64(540), obj.Status.StaticCredsMetaData.TTL)
	assert.Equal(t, int64(600), obj.Status.StaticCredsMetaData.RotationPeriod)
	assert.Equal(t, time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(), obj.Status.StaticCredsMetaData.LastVaultRotation)
	// Two requests: initial doVault + one backoff-loop doVault (inLastSyncRotation=true)
	assert.Len(t, vClient.Requests, 2)
}

// Regression test: on ForceSync (VaultAuth token expiry), Reconcile must
// persist the refreshed TTL and use it for RequeueAfter, even when the HMAC
// matches (no rotation). Exercises the full Reconcile path.
//
// Status before: TTL=600  |  Vault response: TTL=540 (same LastVaultRotation)
func TestVaultDynamicSecretReconciler_Reconcile_forceSyncStaticCredsUsesRefreshedTTL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newStaticCredsFixture(t)

	obj := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "app",
			Namespace:  "default",
			UID:        types.UID("vds-app"),
			Generation: 7,
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount:            "database",
			Path:             "static-creds/app",
			AllowStaticCreds: true,
			Destination: secretsv1beta1.Destination{
				Name:   "app",
				Create: true,
			},
		},
		Status: secretsv1beta1.VaultDynamicSecretStatus{
			LastGeneration: 7,
			SecretMAC:      f.secretMAC,
			VaultClientMeta: secretsv1beta1.VaultClientMeta{
				CacheKey: "cache-key",
				ID:       "client-1",
			},
			StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(),
				RotationPeriod:    600,
				TTL:               600,
			},
		},
	}

	destSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
		},
		Data: f.secretData,
	}

	secretClient := testutils.NewFakeClientBuilder().
		WithStatusSubresource(obj).
		WithObjects(obj, destSecret, f.hmacKeySecret).
		Build()

	vClient := &reconcileTestVaultClient{
		MockRecordingVaultClient: &vault.MockRecordingVaultClient{
			Id: "client-1",
			ReadResponses: map[string][]vault.Response{
				// Two reads: initial doVault + one inside the awaitVaultSecretRotation
				// backoff loop (triggered because inLastSyncRotation=true).
				"database/static-creds/app": {f.freshResponse, f.freshResponse},
			},
		},
		cacheKey: "cache-key",
	}

	syncRegistry := NewSyncRegistry()
	objKey := client.ObjectKeyFromObject(obj)
	syncRegistry.Add(objKey)

	r := &VaultDynamicSecretReconciler{
		Client:                      secretClient,
		SecretsClient:               secretClient,
		ClientFactory:               &reconcileTestClientFactory{client: vClient},
		HMACValidator:               f.validator,
		Recorder:                    record.NewFakeRecorder(10),
		SyncRegistry:                syncRegistry,
		BackOffRegistry:             NewBackOffRegistry(),
		referenceCache:              NewResourceReferenceCache(),
		GlobalTransformationOptions: &helpers.GlobalTransformationOptions{},
	}

	result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: objKey})
	require.NoError(t, err)
	// Two requests: initial doVault + one backoff-loop doVault (inLastSyncRotation=true)
	assert.Len(t, vClient.MockRecordingVaultClient.Requests, 2)
	assert.False(t, syncRegistry.Has(objKey))
	// horizon = TTL(540s) + 500ms (periodic static-creds buffer) + jitter [0, 150ms]
	assert.GreaterOrEqual(t, result.RequeueAfter, 540*time.Second+500*time.Millisecond)
	assert.LessOrEqual(t, result.RequeueAfter, 540*time.Second+650*time.Millisecond)

	updated := &secretsv1beta1.VaultDynamicSecret{}
	require.NoError(t, secretClient.Get(ctx, objKey, updated))
	assert.Equal(t, int64(540), updated.Status.StaticCredsMetaData.TTL)
	assert.Equal(t, int64(600), updated.Status.StaticCredsMetaData.RotationPeriod)
	assert.Equal(t, int64(7), updated.Status.LastGeneration)
	assert.Equal(t, f.secretMAC, updated.Status.SecretMAC)
	// LastVaultRotation is unchanged: no rotation occurred, only the TTL decreased
	assert.Equal(t, time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(), updated.Status.StaticCredsMetaData.LastVaultRotation)
}

// TestVaultDynamicSecretReconciler_isStaticCreds tests that we can appropriately
// identify if a vault credential is "static" by checking the LastVaultRotation,
// RotationPeriod, and RotationSchedule fields
func TestVaultDynamicSecretReconciler_isStaticCreds(t *testing.T) {
	tests := []struct {
		name     string
		metaData *v1beta1.VaultStaticCredsMetaData
		want     bool
	}{
		{
			name: "static-cred-with-rotation-period",
			metaData: &v1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1695430611,
				RotationPeriod:    300,
			},
			want: true,
		},
		{
			name: "not-static-cred-with-rotation-period",
			metaData: &v1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 0,
				RotationPeriod:    0,
			},
			want: false,
		},
		{
			name: "static-cred-with-rotation-schedule",
			metaData: &v1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1695430611,
				RotationSchedule:  "1 0 * * *",
			},
			want: true,
		},
		{
			name: "not-static-cred-with-rotation-schedule",
			metaData: &v1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 0,
				RotationSchedule:  "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &VaultDynamicSecretReconciler{}
			got := r.isStaticCreds(tt.metaData)
			assert.Equalf(t, tt.want, got, "isStaticCreds(%v)", tt.metaData)
		})
	}
}

func Test_computeRotationTime(t *testing.T) {
	// time without nanos, for ease of comparison
	then := time.Unix(nowFunc().Unix(), 0)
	tests := []struct {
		name string
		vds  *secretsv1beta1.VaultDynamicSecret
		want time.Time
	}{
		{
			name: "fifty-percent",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 300,
					},
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 50,
				},
			},
			want: then.Add(150 * time.Second),
		},
		{
			name: "sixty-percent",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 300,
					},
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
				},
			},
			want: then.Add(180 * time.Second),
		},
		{
			name: "zero-percent",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 300,
					},
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 0,
				},
			},
			want: then,
		},
		{
			name: "exceed-renewal-percentage-cap",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 300,
					},
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: renewalPercentCap + 1,
				},
			},
			want: then.Add(time.Duration(float64(time.Second*300) * (float64(renewalPercentCap) / 100))),
		},
		{
			name: "sixty-percent-refreshAfter",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "300s",
				},
			},
			want: then.Add(180 * time.Second),
		},
		{
			name: "sixty-percent-override-refreshAfter",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 300,
					},
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "600s",
				},
			},
			want: then.Add(180 * time.Second),
		},
		{
			name: "invalid-refreshAfter-value",
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					LastRenewalTime: then.Unix(),
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "x",
				},
			},
			want: then,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := computeRotationTime(tt.vds)
			assert.Equalf(t, tt.want, actual, "computeRotationTime(%v)", tt.vds)
		})
	}
}

func Test_computeRelativeHorizonWithJitter(t *testing.T) {
	staticNow := time.Unix(nowFunc().Unix(), 0)
	defaultNowFunc := func() time.Time { return staticNow }

	tests := []struct {
		name           string
		o              *secretsv1beta1.VaultDynamicSecret
		minHorizon     time.Duration
		wantMinHorizon time.Duration
		wantMaxHorizon time.Duration
		wantInWindow   bool
	}{
		{
			// between Vault rotations, will enqueue with a new time horizon
			name: "static-creds-in-rotation-window-after-sync",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: defaultNowFunc().Unix(),
						TTL:               30,
					},
				},
			},
			wantMinHorizon: 30 * time.Second,
			wantMaxHorizon: 30*time.Second + staticCredsJitterHorizon,
			wantInWindow:   true,
		},
		{
			// between Vault rotations, will enqueue with a new time horizon
			name: "static-creds-in-rotation-window-by-1s",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						TTL:               30,
						LastVaultRotation: defaultNowFunc().Unix() - 29,
					},
				},
			},
			minHorizon:     1 * time.Second,
			wantMinHorizon: 1 * time.Second,
			wantMaxHorizon: time.Duration(1.2 * float64(time.Second)),
			wantInWindow:   true,
		},
		{
			// not in Vault rotation window, will rotate.
			name: "static-creds-not-in-rotation-window",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						TTL:               30,
						LastVaultRotation: defaultNowFunc().Unix() - 30,
					},
				},
			},
			minHorizon:     1 * time.Second,
			wantMinHorizon: 1 * time.Second,
			wantMaxHorizon: time.Duration(1.2 * float64(time.Second)),
			wantInWindow:   false,
		},
		{
			name: "lease-not-in-window-now",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 90,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					LastRenewalTime: defaultNowFunc().Unix(),
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 100,
					},
				},
			},
			minHorizon:     1 * time.Second,
			wantMinHorizon: time.Duration(85.5 * float64(time.Second)),
			wantMaxHorizon: 90 * time.Second,
			wantInWindow:   false,
		},
		{
			name: "lease-in-window",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 89,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					LastRenewalTime: defaultNowFunc().Unix() - 90,
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 100,
					},
				},
			},
			minHorizon:     1 * time.Second,
			wantMinHorizon: time.Duration(.8 * float64(time.Second)),
			wantMaxHorizon: 1 * time.Second,
			wantInWindow:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isStatic := tt.o.Status.StaticCredsMetaData.TTL > 0

			nowFuncOrig := nowFunc
			t.Cleanup(func() {
				nowFunc = nowFuncOrig
			})
			nowFunc = defaultNowFunc
			gotHorizon, gotInWindow := computeRelativeHorizonWithJitter(tt.o, tt.minHorizon)
			assert.Equalf(t, tt.wantInWindow, gotInWindow, "computeRelativeHorizonWithJitter(%v, %v)", tt.o, tt.minHorizon)
			if isStatic {
				assert.LessOrEqualf(t, tt.wantMinHorizon, gotHorizon,
					"computeRelativeHorizonWithJitter(%v, %v)", tt.o, tt.minHorizon)
				assert.GreaterOrEqualf(t, tt.wantMaxHorizon, gotHorizon,
					"computeRelativeHorizonWithJitter(%v, %v)", tt.o, tt.minHorizon)
			} else {
				assert.LessOrEqualf(t, gotHorizon, tt.wantMaxHorizon,
					"computeRelativeHorizonWithJitter(%v, %v)", tt.o, tt.minHorizon)
				assert.GreaterOrEqualf(t, gotHorizon, tt.wantMinHorizon,
					"computeRelativeHorizonWithJitter(%v, %v)", tt.o, tt.minHorizon)
			}
		})
	}
}

func TestVaultDynamicSecretReconciler_computePostSyncHorizon(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		o              *secretsv1beta1.VaultDynamicSecret
		wantMinHorizon time.Duration
		wantMaxHorizon time.Duration
	}{
		{
			name: "static-creds",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: nowFunc().Unix() - 30,
						RotationPeriod:    60,
						TTL:               30,
					},
				},
			},
			wantMinHorizon: time.Duration(30 * float64(time.Second)),
			// max jitter 150000000
			wantMaxHorizon: time.Duration(30.65 * float64(time.Second)),
		},
		{
			name: "static-creds-ttl-0",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: nowFunc().Unix() - 30,
						RotationPeriod:    60,
						TTL:               0,
					},
				},
			},
			wantMinHorizon: time.Duration(1 * float64(time.Second)),
			// max jitter 150000000
			wantMaxHorizon: time.Duration(1.15 * float64(time.Second)),
		},
		{
			name: "allowed-but-not-static-creds-response",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{},
			},
			wantMinHorizon: 0,
			wantMaxHorizon: 0,
		},
		{
			name: "leased",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 100,
					},
				},
			},
			wantMaxHorizon: time.Second * 70,
			wantMinHorizon: time.Second * 60,
		},
		{
			name: "leased-with-refreshAfter",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "200s",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 100,
					},
				},
			},
			wantMaxHorizon: time.Second * 70,
			wantMinHorizon: time.Second * 60,
		},
		{
			name: "not-leased-with-refreshAfter",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "100s",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{},
				},
			},
			wantMaxHorizon: time.Second * 70,
			wantMinHorizon: time.Second * 60,
		},
		{
			name: "invalid-refreshAfter",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 60,
					RefreshAfter:   "x",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{},
				},
			},
			wantMaxHorizon: 0,
			wantMinHorizon: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &VaultDynamicSecretReconciler{}
			got := r.computePostSyncHorizon(ctx, tt.o)
			assert.GreaterOrEqualf(t, got, tt.wantMinHorizon, "computePostSyncHorizon(%v, %v)", ctx, tt.o)
			assert.LessOrEqualf(t, got, tt.wantMaxHorizon, "computePostSyncHorizon(%v, %v)", ctx, tt.o)
		})
	}
}

type stubVaultClient struct {
	vault.Client
	cacheKey           vault.ClientCacheKey
	credentialProvider provider.CredentialProviderBase
}

func (c *stubVaultClient) GetCacheKey() (vault.ClientCacheKey, error) {
	return c.cacheKey, nil
}

func (c *stubVaultClient) GetCredentialProvider() provider.CredentialProviderBase {
	return c.credentialProvider
}

type stubCredentialProvider struct {
	provider.CredentialProviderBase
	namespace string
}

func (p *stubCredentialProvider) GetNamespace() string {
	return p.namespace
}

func TestVaultDynamicSecretReconciler_vaultClientCallback(t *testing.T) {
	key1 := fmt.Sprintf("%s-%s", consts.ProviderMethodKubernetes, "2a8108711ae49ac0faa724")
	key2 := fmt.Sprintf("%s-%s", consts.ProviderMethodKubernetes, "2a8108711ae49ac0faa725")

	// instances in the same namespace that should be included by the callback.
	instances := []*secretsv1beta1.VaultDynamicSecret{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "baz",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: key1,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "baz-ns",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: fmt.Sprintf("%s-ns1/ns2", key1),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "canary-invalid-key",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: fmt.Sprintf("%s-ns1/ns2", key1[:len(key1)-1]),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "canary-other-key-and-vault-ns",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: fmt.Sprintf("%s-ns1/ns2", key2),
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "canary-other-key",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: key2,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "other",
				Name:      "canary-other-k8s-ns",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: key2,
				},
			},
		},
	}

	tests := []struct {
		name      string
		c         vault.Client
		client    client.Client
		create    int
		want      []any
		instances []*secretsv1beta1.VaultDynamicSecret
	}{
		{
			name:      "matching-instances",
			instances: instances,
			c: &stubVaultClient{
				cacheKey:           vault.ClientCacheKey(key1),
				credentialProvider: &stubCredentialProvider{namespace: "default"},
			},
			want: []any{
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "baz",
						Namespace: "default",
					},
				},
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "baz-ns",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "none",
			c: &stubVaultClient{
				cacheKey:           "kubernetes-12345",
				credentialProvider: &stubCredentialProvider{namespace: "default"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			syncRegistry := NewSyncRegistry()
			r := &VaultDynamicSecretReconciler{
				Client:       testutils.NewFakeClient(),
				SyncRegistry: syncRegistry,
				SourceCh:     make(chan event.GenericEvent),
			}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() {
				cancel()
				close(r.SourceCh)
			})

			for _, o := range tt.instances {
				require.NoError(t, r.Create(ctx, o))
			}

			handler := &enqueueDelayingSyncEventHandler{
				enqueueDurationForJitter: time.Second * 2,
			}
			cs := source.Channel(r.SourceCh, handler)

			q := &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			}

			go func() {
				err := cs.Start(ctx, q)
				require.NoError(t, err, "cs.Start")
			}()

			r.vaultClientCallback(ctx, tt.c)
			assert.Eventuallyf(t, func() bool {
				return len(q.AddedAfter) == len(tt.want)
			}, handler.enqueueDurationForJitter, time.Millisecond*500,
				"expected %d syncs, got %d", len(tt.want), len(q.AddedAfter))

			assert.ElementsMatchf(t, tt.want, q.AddedAfter,
				"vaultClientCallback(%v, %v)", ctx, tt.client)

			for _, d := range q.AddedAfterDuration {
				assert.Greater(t, d, time.Duration(0), "expected positive duration")
				assert.LessOrEqual(t, d, handler.enqueueDurationForJitter,
					"expected duration to be less than %s",
					handler.enqueueDurationForJitter)
			}
		})
	}
}

func Test_vaultStaticCredsMetaDataFromData(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]any
		want    *secretsv1beta1.VaultStaticCredsMetaData
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "with-rotation-schedule",
			data: map[string]any{
				"last_vault_rotation": "2024-05-01T23:18:01.330875393Z",
				"rotation_schedule":   "1 0 * * *",
				"ttl":                 30,
			},
			want: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1714605481,
				RotationSchedule:  "1 0 * * *",
				TTL:               30,
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-rotation-period",
			data: map[string]any{
				"last_vault_rotation": "2024-05-01T23:18:01.330875393Z",
				"rotation_period":     600,
				"ttl":                 30,
			},
			want: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1714605481,
				RotationPeriod:    600,
				TTL:               30,
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-last_vault_rotation",
			data: map[string]any{
				"last_vault_rotation": "2-024-05-01T23:18:01.330875393Z",
				"rotation_schedule":   "1 0 * * *",
				"ttl":                 30,
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "invalid last_vault_rotation", i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := vaultStaticCredsMetaDataFromData(tt.data)
			if !tt.wantErr(t, err, fmt.Sprintf("vaultStaticCredsMetaDataFromData(%v)", tt.data)) {
				return
			}
			assert.Equalf(t, tt.want, got, "vaultStaticCredsMetaDataFromData(%v)", tt.data)
		})
	}
}

type vaultResponse struct {
	secret *api.Secret
	data   map[string]any
	k8s    map[string][]byte
}

func (s *vaultResponse) WrapInfo() *api.SecretWrapInfo {
	// TODO implement me
	panic("implement me")
}

func (s *vaultResponse) Secret() *api.Secret {
	return s.secret
}

func (s *vaultResponse) Data() map[string]any {
	return s.data
}

func (s *vaultResponse) SecretK8sData(_ *helpers.SecretTransformationOption) (map[string][]byte, error) {
	return s.k8s, nil
}

func TestVaultDynamicSecretReconciler_awaitRotation(t *testing.T) {
	tslVal0 := "2024-05-02T19:48:01.328261545Z"
	ts0, err := time.Parse(time.RFC3339Nano, tslVal0)
	require.NoError(t, err)

	tsVal1 := "2024-05-02T19:49:01.325799425Z"
	ts1, err := time.Parse(time.RFC3339Nano, tsVal1)
	require.NoError(t, err)

	ctx := context.Background()
	tests := []struct {
		name                    string
		o                       *secretsv1beta1.VaultDynamicSecret
		c                       *vault.MockRecordingVaultClient
		initialResponse         vault.Response
		wantStaticCredsMetaData *secretsv1beta1.VaultStaticCredsMetaData
		wantResponse            vault.Response
		wantRequestCount        int
		wantErr                 assert.ErrorAssertionFunc
	}{
		{
			name: "invalid-static-creds-meta-data",
			c:    &vault.MockRecordingVaultClient{},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": "2-024-05-02T19:48:01.328261545Z",
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_schedule":   "*/1 * * * *",
					"rotation_window":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "invalid last_vault_rotation", i...)
			},
		},
		{
			name: "not-static-creds",
			c:    &vault.MockRecordingVaultClient{},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"username": "foo",
					"password": "bar",
				},
			},
			wantErr: assert.NoError,
			wantResponse: &vaultResponse{
				data: map[string]any{
					"username": "foo",
					"password": "bar",
				},
			},
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{},
			wantRequestCount:        0,
		},
		{
			name: "empty-last-rotation-schedule",
			c:    &vault.MockRecordingVaultClient{},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_schedule":   "*/1 * * * *",
					"rotation_window":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantErr: assert.NoError,
			o: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						TTL:               55,
					},
				},
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_schedule":   "*/1 * * * *",
					"rotation_window":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts0.Unix(),
				RotationSchedule:  "*/1 * * * *",
				TTL:               59,
			},
			wantRequestCount: 0,
		},
		{
			name: "static-creds-periodic-rotation-rotated",
			c:    &vault.MockRecordingVaultClient{},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_period":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-xxx",
				},
			},
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/periodic",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						TTL:               59,
					},
				},
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_period":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-xxx",
				},
			},
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationPeriod:    3600,
				TTL:               59,
			},
			wantRequestCount: 0,
			wantErr:          assert.NoError,
		},
		{
			name: "static-creds-periodic-rotation-near-rotation",
			c: &vault.MockRecordingVaultClient{
				CheckPaths: true,
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/periodic": {
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tsVal1,
								"password":            "Y3pro72-fl1ndHTFOg9h",
								"rotation_period":     3600,
								"ttl":                 59,
								"username":            "dev-postgres-static-user-xxx",
							},
						},
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_period":     3600,
					"ttl":                 2,
					"username":            "dev-postgres-static-user-xxx",
				},
			},
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/periodic",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						TTL:               59,
					},
				},
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_period":     3600,
					"ttl":                 59,
					"username":            "dev-postgres-static-user-xxx",
				},
			},
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationPeriod:    3600,
				TTL:               59,
			},
			wantRequestCount: 1,
			wantErr:          assert.NoError,
		},
		{
			name: "static-creds-scheduled-initial-ttl-zero",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/scheduled",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						RotationSchedule:  "*/1 * * * *",
						TTL:               55,
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "Y3pro72-fl1ndHTFOg9h",
					"rotation_schedule":   "*/1 * * * *",
					"rotation_window":     3600,
					"ttl":                 0,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantErr: assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationSchedule:  "*/1 * * * *",
				TTL:               58,
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "qSGA-u8f1-H6WYkII4Yn",
					"rotation_schedule":   "*/1 * * * *",
					"rotation_window":     3600,
					"ttl":                 58,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			c: &vault.MockRecordingVaultClient{
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tslVal0,
								"password":            "Y3pro72-fl1ndHTFOg9h",
								"rotation_schedule":   "*/1 * * * *",
								"rotation_window":     3600,
								"ttl":                 59,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tsVal1,
								"password":            "qSGA-u8f1-H6WYkII4Yn",
								"rotation_schedule":   "*/1 * * * *",
								"rotation_window":     3600,
								"ttl":                 58,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
					},
				},
			},
			wantRequestCount: 2,
		},
		{
			// Regression: even schedule where the next TTL equals the last sync TTL.
			// The >= check fires (60 >= 60), so retries should happen.
			name: "static-creds-scheduled-ttl-equal-last-sync-ttl",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/scheduled",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						RotationSchedule:  "*/1 * * * *",
						TTL:               60,
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "oldpassword",
					"rotation_schedule":   "*/1 * * * *",
					"ttl":                 60,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			c: &vault.MockRecordingVaultClient{
				CheckPaths: true,
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						// Poll 1: still same LastVaultRotation, TTL == lastSyncTTL → retry
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tslVal0,
								"password":            "oldpassword",
								"rotation_schedule":   "*/1 * * * *",
								"ttl":                 60,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
						// Poll 2: rotated
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tsVal1,
								"password":            "newpassword",
								"rotation_schedule":   "*/1 * * * *",
								"ttl":                 58,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationSchedule:  "*/1 * * * *",
				TTL:               58,
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "newpassword",
					"rotation_schedule":   "*/1 * * * *",
					"ttl":                 58,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantRequestCount: 2,
		},
		{
			// Regression: classic TTL rollover bug where the next TTL is greater than
			// the last sync TTL. The >= check fires (600 >= 240), so retries happen.
			name: "static-creds-scheduled-ttl-greater-than-last-sync-ttl",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/scheduled",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						RotationSchedule:  "*/4 * * * *",
						TTL:               240,
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "oldpassword",
					"rotation_schedule":   "*/4 * * * *",
					"ttl":                 240,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			c: &vault.MockRecordingVaultClient{
				CheckPaths: true,
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						// Poll 1: TTL rolled over to larger value (rollover bug) → retry
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tslVal0,
								"password":            "oldpassword",
								"rotation_schedule":   "*/4 * * * *",
								"ttl":                 600,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
						// Poll 2: rotated
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tsVal1,
								"password":            "newpassword",
								"rotation_schedule":   "*/4 * * * *",
								"ttl":                 58,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationSchedule:  "*/4 * * * *",
				TTL:               58,
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "newpassword",
					"rotation_schedule":   "*/4 * * * *",
					"ttl":                 58,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantRequestCount: 2,
		},
		{
			// Bug: uneven rotation schedule (e.g. "30 3,16 * * *") where the next
			// interval is shorter than the last sync TTL. Vault resets the TTL for
			// the shorter interval (39600 < 46800) before updating LastVaultRotation
			// due to DB lag. The old ">= lastSyncTTL" check misses this case —
			// the loop exits immediately with stale credentials instead of retrying.
			name: "static-creds-scheduled-ttl-less-than-last-sync-ttl-uneven-schedule",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/scheduled",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						RotationSchedule:  "30 3,16 * * *",
						// 13h — last synced after the 3:30 rotation, next rotation at 16:30
						TTL: 46800,
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "oldpassword",
					"rotation_schedule":   "30 3,16 * * *",
					// Vault reset TTL to 11h (shorter slot: 16:30→3:30) but
					// LastVaultRotation not yet updated due to DB lag.
					"ttl":      39600,
					"username": "dev-postgres-static-user-scheduled",
				},
			},
			c: &vault.MockRecordingVaultClient{
				CheckPaths: true,
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						// Poll 1: still stale — LastVaultRotation unchanged, TTL < lastSyncTTL.
						// The old code exits here without retrying (the bug).
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tslVal0,
								"password":            "oldpassword",
								"rotation_schedule":   "30 3,16 * * *",
								"ttl":                 39600,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
						// Poll 2: DB lag cleared, rotation complete.
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tsVal1,
								"password":            "newpassword",
								"rotation_schedule":   "30 3,16 * * *",
								"ttl":                 39598,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts1.Unix(),
				RotationSchedule:  "30 3,16 * * *",
				TTL:               39598,
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tsVal1,
					"password":            "newpassword",
					"rotation_schedule":   "30 3,16 * * *",
					"ttl":                 39598,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			wantRequestCount: 2,
		},
		{
			// Remediation: K8s destination secret deleted mid-cycle on an uneven
			// schedule. TTL has naturally decreased since last sync — no Vault
			// rotation occurred. The function must NOT retry; it should return
			// the current (valid) credentials so the controller can re-create
			// the K8s secret.
			name: "static-creds-scheduled-remediation-mid-cycle-uneven",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					Mount: "mount",
					Path:  "static-creds/scheduled",
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					LastRenewalTime: nowFunc().Unix() - 3600, // synced 1h ago
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts0.Unix(),
						RotationSchedule:  "30 3,16 * * *",
						// 13h — TTL at the time of last sync
						TTL: 46800,
					},
				},
			},
			initialResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "samepassword",
					"rotation_schedule":   "30 3,16 * * *",
					// TTL naturally decreased by ~1h (46800 - 3600 = 43200)
					"ttl":      43200,
					"username": "dev-postgres-static-user-scheduled",
				},
			},
			c: &vault.MockRecordingVaultClient{
				CheckPaths: true,
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						// Single poll: same LastVaultRotation, TTL naturally decreased.
						// expectedTTL = 46800 - 3600 = 43200 (not near zero),
						// so neither TTL reset check fires → no retry.
						&vaultResponse{
							data: map[string]any{
								"last_vault_rotation": tslVal0,
								"password":            "samepassword",
								"rotation_schedule":   "30 3,16 * * *",
								"ttl":                 43200,
								"username":            "dev-postgres-static-user-scheduled",
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts0.Unix(),
				RotationSchedule:  "30 3,16 * * *",
				TTL:               43200,
			},
			wantResponse: &vaultResponse{
				data: map[string]any{
					"last_vault_rotation": tslVal0,
					"password":            "samepassword",
					"rotation_schedule":   "30 3,16 * * *",
					"ttl":                 43200,
					"username":            "dev-postgres-static-user-scheduled",
				},
			},
			// One doVault call in the loop, no retry — returns immediately.
			wantRequestCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &VaultDynamicSecretReconciler{}
			got, got1, err := r.awaitVaultSecretRotation(ctx, tt.o, tt.c, tt.initialResponse)
			if !tt.wantErr(t, err, fmt.Sprintf("awaitVaultSecretRotation(%v, %v, %v, %v)", ctx, tt.o, tt.c, tt.initialResponse)) {
				return
			}
			assert.Equalf(t, tt.wantStaticCredsMetaData, got, "awaitVaultSecretRotation(%v, %v, %v, %v)", ctx, tt.o, tt.c, tt.initialResponse)
			assert.Equalf(t, tt.wantResponse, got1, "awaitVaultSecretRotation(%v, %v, %v, %v)", ctx, tt.o, tt.c, tt.initialResponse)
			assert.Equalf(t, tt.wantRequestCount, len(tt.c.Requests), "awaitVaultSecretRotation(%v, %v, %v, %v)", ctx, tt.o, tt.c, tt.initialResponse)
		})
	}
}

func init() {
	_ = secretsv1beta1.AddToScheme(scheme.Scheme)
}

// TestEventPathForEngine tests the eventPathForEngine function.
func TestEventPathForEngine(t *testing.T) {
	tests := []struct {
		name       string
		engineType string
		want       string
		wantErr    bool
	}{
		{name: "database", engineType: vsoconsts.VaultEngineTypeDatabase, want: databaseEventPath},
		{name: "ldap", engineType: vsoconsts.VaultEngineTypeLDAP, want: ldapEventPath},
		{name: "empty", engineType: "", wantErr: true},
		{name: "unsupported", engineType: "kv", wantErr: true},
		{name: "case-sensitive", engineType: "Database", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eventPathForEngine(tt.engineType)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func newVDSForMatch(mount, path, namespace string) *secretsv1beta1.VaultDynamicSecret {
	return &secretsv1beta1.VaultDynamicSecret{
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount:     mount,
			Path:      path,
			Namespace: namespace,
		},
	}
}

func newEvent(eventType, mountPath, name, namespace string) *dynamicSecretEventMsg {
	ev := &dynamicSecretEventMsg{}
	ev.Data.EventType = eventType
	ev.Data.PluginInfo.MountPath = mountPath
	ev.Data.Event.Metadata.Name = name
	ev.Data.Namespace = namespace
	return ev
}

// TestMatchEvent tests the matchEvent function to ensure it correctly matches events to VaultDynamicSecret objects
// based on event type, mount path, role name, and namespace.
// It includes various test cases covering happy paths and edge cases for mismatches.
func TestMatchEvent(t *testing.T) {
	tests := []struct {
		name string
		o    *secretsv1beta1.VaultDynamicSecret
		ev   *dynamicSecretEventMsg
		want bool
	}{
		{
			name: "happy-database-rotate",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-database-rotate",
			o:    newVDSForMatch("database", "creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-database-static-creds-create",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/static-creds-create", "database/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-database-role-update",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/role-update", "database/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-ldap-rotate",
			o:    newVDSForMatch("ldap", "static-cred/myrole", ""),
			ev:   newEvent("ldap/rotate", "ldap/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-ldap-static-role-update",
			o:    newVDSForMatch("ldap", "static-cred/myrole", ""),
			ev:   newEvent("ldap/static-role-update", "ldap/", "myrole", ""),
			want: true,
		},
		{
			name: "happy-ldap-rotate-nested-role-name",
			o:    newVDSForMatch("ldap", "static-cred/group1/group2/myrole", ""),
			ev:   newEvent("ldap/rotate", "ldap/", "group1/group2/myrole", ""),
			want: true,
		},
		{
			name: "happy-database-namespace-with-leading-slash-on-event",
			o:    newVDSForMatch("database", "static-creds/myrole", "ns1"),
			ev:   newEvent("database/rotate", "database/", "myrole", "/ns1/"),
			want: true,
		},
		{
			name: "happy-mount-without-trailing-slash-on-spec",
			o:    newVDSForMatch("database/", "static-creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "myrole", ""),
			want: true,
		},
		{
			name: "rejected-event-type-not-in-allowlist",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/role-create", "database/", "myrole", ""),
			want: false,
		},
		{
			name: "rejected-database-root-rotate",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/root-rotate", "database/", "myrole", ""),
			want: false,
		},
		{
			name: "rejected-kv-event-on-database-watcher",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("kv-v2/data-write", "database/", "myrole", ""),
			want: false,
		},
		{
			name: "rejected-namespace-mismatch",
			o:    newVDSForMatch("database", "static-creds/myrole", "ns1"),
			ev:   newEvent("database/rotate", "database/", "myrole", "ns2"),
			want: false,
		},
		{
			name: "rejected-mount-mismatch",
			o:    newVDSForMatch("db", "static-creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "myrole", ""),
			want: false,
		},
		{
			name: "rejected-role-name-mismatch",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "otherrole", ""),
			want: false,
		},
		{
			name: "rejected-role-name-substring-without-segment-boundary",
			o:    newVDSForMatch("database", "static-creds/notmyrole", ""),
			ev:   newEvent("database/rotate", "database/", "myrole", ""),
			want: false,
		},
		{
			name: "rejected-empty-event-name",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("database/rotate", "database/", "", ""),
			want: false,
		},
		{
			name: "rejected-empty-event-type",
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			ev:   newEvent("", "database/", "myrole", ""),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchEvent(tt.o, tt.ev))
		})
	}
}

// TestMatchEvent_JSONRoundTrip tests that the matchEvent function correctly matches events to VaultDynamicSecret objects
func TestMatchEvent_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		o       *secretsv1beta1.VaultDynamicSecret
		want    bool
	}{
		{
			name: "root-namespace-event-omits-namespace-field",
			payload: `{
				"id":"abc",
				"data":{
					"event":{
						"id":"abc",
						"metadata":{
							"path":"database/rotate-role/myrole",
							"name":"myrole",
							"operation":"rotate",
							"modified":"true"
						}
					},
					"event_type":"database/rotate",
					"plugin_info":{
						"mount_class":"secret",
						"mount_path":"database/",
						"plugin":"database"
					}
				}
			}`,
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			want: true,
		},
		{
			name: "root-namespace-event-with-explicit-empty-namespace",
			payload: `{
				"data":{
					"event":{
						"metadata":{
							"path":"database/rotate-role/myrole",
							"name":"myrole",
							"operation":"rotate",
							"modified":"true"
						}
					},
					"event_type":"database/rotate",
					"plugin_info":{"mount_path":"database/"},
					"namespace":""
				}
			}`,
			o:    newVDSForMatch("database", "static-creds/myrole", ""),
			want: true,
		},
		{
			name: "root-namespace-event-rejected-by-namespaced-vds",
			payload: `{
				"data":{
					"event":{
						"metadata":{
							"name":"myrole",
							"modified":"true"
						}
					},
					"event_type":"database/rotate",
					"plugin_info":{"mount_path":"database/"}
				}
			}`,
			o:    newVDSForMatch("database", "static-creds/myrole", "ns1"),
			want: false,
		},
		{
			name: "child-namespace-event-with-trailing-slash",
			payload: `{
				"data":{
					"event":{
						"metadata":{
							"name":"myrole",
							"modified":"true"
						}
					},
					"event_type":"database/rotate",
					"plugin_info":{"mount_path":"database/"},
					"namespace":"ns1/"
				}
			}`,
			o:    newVDSForMatch("database", "static-creds/myrole", "ns1"),
			want: true,
		},
		{
			name: "ldap-rotate-nested-role-name-real-payload",
			payload: `{
				"id":"8fea78ca-47c5-0057-fc6f-38a631e4c0e5",
				"data":{
					"event":{
						"id":"8fea78ca-47c5-0057-fc6f-38a631e4c0e5",
						"metadata":{
							"modified":"true",
							"name":"group1/group2/myrole",
							"operation":"rotate",
							"path":"ldap/rotate-role/group1/group2/myrole"
						}
					},
					"event_type":"ldap/rotate",
					"plugin_info":{"mount_path":"ldap/","plugin":"ldap"}
				}
			}`,
			o:    newVDSForMatch("ldap", "static-cred/group1/group2/myrole", ""),
			want: true,
		},
		{
			name: "ldap-rotate-nested-role-name-rejected-when-nesting-doesnt-match",
			payload: `{
				"data":{
					"event":{
						"metadata":{
							"modified":"true",
							"name":"group1/group2/myrole",
							"operation":"rotate"
						}
					},
					"event_type":"ldap/rotate",
					"plugin_info":{"mount_path":"ldap/","plugin":"ldap"}
				}
			}`,
			o:    newVDSForMatch("ldap", "static-cred/myrole", ""),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := dynamicSecretEventMsg{}
			require.NoError(t, json.Unmarshal([]byte(tt.payload), &ev))
			assert.Equal(t, tt.want, matchEvent(tt.o, &ev))
		})
	}
}

func newVDS(name, namespace string, syncCfg *secretsv1beta1.VaultDynamicSecretSyncConfig) *secretsv1beta1.VaultDynamicSecret {
	return &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount:      "database",
			Path:       "static-creds/myrole",
			SyncConfig: syncCfg,
		},
	}
}

// TestVDS_UnWatchEvents tests the unWatchEvents function to ensure it correctly unregisters event watchers
// and cancels their contexts. It verifies that the registry is updated and that the context is canceled as expected.
func TestVDS_UnWatchEvents(t *testing.T) {
	r := &VaultDynamicSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
	}
	o := newVDS("foo", "default", nil)

	r.unWatchEvents(o)

	ctx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)
	r.eventWatcherRegistry.Register(client.ObjectKeyFromObject(o), &eventWatcherMeta{
		Cancel:         cancel,
		StoppedCh:      stoppedCh,
		LastGeneration: 1,
		LastClientID:   "id-1",
	})
	require.Equal(t, 1, r.eventWatcherRegistry.registry.ItemCount())

	r.unWatchEvents(o)
	assert.Equal(t, 0, r.eventWatcherRegistry.registry.ItemCount())
	assert.ErrorIs(t, ctx.Err(), context.Canceled)

	r.unWatchEvents(o)
}

func TestVDS_EnsureEventWatcher_NilSyncConfig(t *testing.T) {
	r := &VaultDynamicSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
	}
	o := newVDS("foo", "default", nil)
	err := r.ensureEventWatcher(context.Background(), o, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "syncConfig is nil")
	assert.Equal(t, 0, r.eventWatcherRegistry.registry.ItemCount())
}

func TestVDS_EnsureEventWatcher_InvalidEngineType(t *testing.T) {
	r := &VaultDynamicSecretReconciler{
		eventWatcherRegistry: newEventWatcherRegistry(),
	}
	o := newVDS("foo", "default", &secretsv1beta1.VaultDynamicSecretSyncConfig{
		InstantUpdates: true,
		EngineType:     "kv",
	})
	err := r.ensureEventWatcher(context.Background(), o, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported engineType")
	assert.Equal(t, 0, r.eventWatcherRegistry.registry.ItemCount())
}

// TestVDS_EnsureEventWatcher_RegistersWatcher tests that ensureEventWatcher correctly registers an event
// watcher for a valid VaultDynamicSecret object.
func TestVDS_HandleDeletionStopsWatcher(t *testing.T) {
	o := newVDS("foo", "default", &secretsv1beta1.VaultDynamicSecretSyncConfig{
		InstantUpdates: true,
		EngineType:     "database",
	})
	o.Finalizers = []string{vaultDynamicSecretFinalizer}

	c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(o).Build()
	r := &VaultDynamicSecretReconciler{
		Client:               c,
		Recorder:             record.NewFakeRecorder(8),
		SyncRegistry:         NewSyncRegistry(),
		BackOffRegistry:      NewBackOffRegistry(),
		referenceCache:       NewResourceReferenceCache(),
		eventWatcherRegistry: newEventWatcherRegistry(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	stoppedCh := make(chan struct{}, 1)
	r.eventWatcherRegistry.Register(client.ObjectKeyFromObject(o), &eventWatcherMeta{
		Cancel:         cancel,
		StoppedCh:      stoppedCh,
		LastGeneration: 1,
		LastClientID:   "id-1",
	})
	require.Equal(t, 1, r.eventWatcherRegistry.registry.ItemCount())

	r.unWatchEvents(o)
	assert.Equal(t, 0, r.eventWatcherRegistry.registry.ItemCount())
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}

func TestVDS_StreamMatchTriggersSync_FilterOnly(t *testing.T) {
	r := &VaultDynamicSecretReconciler{
		SyncRegistry: NewSyncRegistry(),
		SourceCh:     make(chan event.GenericEvent, 1),
	}
	o := newVDS("foo", "default", &secretsv1beta1.VaultDynamicSecretSyncConfig{
		InstantUpdates: true,
		EngineType:     "database",
	})

	ev := newEvent("database/rotate", "database/", "myrole", "")
	require.True(t, matchEvent(o, ev), "expected match for the test event")

	key := client.ObjectKeyFromObject(o)
	r.SyncRegistry.Add(key)
	r.SourceCh <- event.GenericEvent{
		Object: &secretsv1beta1.VaultDynamicSecret{
			ObjectMeta: metav1.ObjectMeta{Name: o.Name, Namespace: o.Namespace},
		},
	}

	assert.True(t, r.SyncRegistry.Has(key))
	select {
	case got := <-r.SourceCh:
		assert.Equal(t, o.Name, got.Object.GetName())
		assert.Equal(t, o.Namespace, got.Object.GetNamespace())
	default:
		t.Fatal("expected a GenericEvent on SourceCh")
	}
}

// TestVDS_StreamFilterDropsNonMatchingEvent tests that non-matching events are correctly
// filtered out and do not trigger a sync.
func TestVDS_StreamFilterDropsNonMatchingEvent(t *testing.T) {
	o := newVDS("foo", "default", &secretsv1beta1.VaultDynamicSecretSyncConfig{
		InstantUpdates: true,
		EngineType:     "database",
	})

	cases := []*dynamicSecretEventMsg{
		newEvent("kv-v2/data-write", "database/", "myrole", ""),     // wrong event type (not in allow-list)
		newEvent("database/role-create", "database/", "myrole", ""), // wrong event type (not in allow-list)
		newEvent("database/rotate", "database/", "otherrole", ""),   // role-name mismatch (Spec.Path = static-creds/myrole)
		newEvent("database/rotate", "db/", "myrole", ""),            // mount path mismatch (Spec.Path = static-creds/myrole)
	}
	for _, ev := range cases {
		assert.False(t, matchEvent(o, ev),
			"unexpected match for event_type=%s mount=%s name=%s",
			ev.Data.EventType, ev.Data.PluginInfo.MountPath, ev.Data.Event.Metadata.Name)
	}
}
