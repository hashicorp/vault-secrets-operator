// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"crypto/sha256"
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
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

type testHMACValidator struct{}

func (v *testHMACValidator) HMAC(_ context.Context, _ client.Client, message []byte) ([]byte, error) {
	sum := sha256.Sum256(message)
	ret := make([]byte, len(sum))
	copy(ret, sum[:])
	return ret, nil
}

func (v *testHMACValidator) Validate(ctx context.Context, c client.Client, message, _ []byte) (bool, []byte, error) {
	newMAC, err := v.HMAC(ctx, c, message)
	if err != nil {
		return false, nil, err
	}
	return true, newMAC, nil
}

type reconcileTestClientFactory struct {
	client vault.Client
}

func (f *reconcileTestClientFactory) Get(context.Context, client.Client, client.Object) (vault.Client, error) {
	return f.client, nil
}

func (f *reconcileTestClientFactory) RegisterClientCallbackHandler(vault.ClientCallbackHandler) {}

// reconcileTestVaultClient implements vault.Client for Reconcile-path tests.
// It embeds vault.Client (nil) to satisfy all interface methods not explicitly
// overridden — those methods must not be called during the test, or the nil
// interface will panic (same pattern as stubVaultClient).
// MockRecordingVaultClient is held as a named field to avoid Go's ambiguity
// rule, which would otherwise suppress Read/Write/ID/Taint promotion when both
// an interface and a struct embedding provide those same method names.
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

// TestVaultDynamicSecretReconciler_syncSecret_staticCredsRefreshesStatusOnMatchingHMAC
// covers the static-creds case where Vault returns a fresh TTL for a periodic
// static-creds role but the secret data and LastVaultRotation are unchanged.
// This tests the scenario: the VaultAuth token expires, causing a
// ForceSync, but no Vault rotation has occurred in the meantime.
//
// Covered behavior:
//   - static creds are allowed and returned from Vault
//   - the destination Secret already contains the same username/password
//   - LastVaultRotation is identical to the stored status (no rotation happened)
//   - awaitVaultSecretRotation enters the backoff loop (inLastSyncRotation=true)
//     and makes a second Vault request, which returns the same data
//   - the stored SecretMAC matches the newly computed HMAC
//   - syncSecret therefore does not rewrite the Secret (`updated == false`)
//   - syncSecret still refreshes status metadata: TTL is updated from the
//     fresh Vault response even though LastVaultRotation is unchanged
//
// Previous status: TTL=600, LastVaultRotation=12:00
// Refreshed Vault metadata: TTL=540, LastVaultRotation=12:00
func TestVaultDynamicSecretReconciler_syncSecret_staticCredsRefreshesStatusOnMatchingHMAC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	freshResponse := &vaultResponse{
		secret: &api.Secret{},
		data: map[string]any{
			"last_vault_rotation": "2026-04-21T12:00:00Z",
			"rotation_period":     600,
			"ttl":                 540,
			"username":            "db-user",
			"password":            "db-pass",
		},
		k8s: map[string][]byte{
			"username": []byte("db-user"),
			"password": []byte("db-pass"),
		},
	}
	vClient := &vault.MockRecordingVaultClient{
		ReadResponses: map[string][]vault.Response{
			// Two responses: one for the initial doVault call in syncSecret, one
			// for the doVault call inside the awaitVaultSecretRotation backoff loop
			// (triggered because inLastSyncRotation=true).
			"database/static-creds/app": {freshResponse, freshResponse},
		},
	}

	validator := &testHMACValidator{}
	message, err := json.Marshal(map[string][]byte{
		"password": []byte("db-pass"),
		"username": []byte("db-user"),
	})
	require.NoError(t, err)
	messageMAC, err := validator.HMAC(ctx, nil, message)
	require.NoError(t, err)

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
			SecretMAC: base64.StdEncoding.EncodeToString(messageMAC),
			StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(),
				RotationPeriod:    600,
				TTL:               600,
			},
		},
	}

	secretClient := fake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("db-user"),
			"password": []byte("db-pass"),
		},
	}).Build()

	r := &VaultDynamicSecretReconciler{
		Client:        secretClient,
		SecretsClient: secretClient,
		HMACValidator: validator,
	}

	lease, updated, err := r.syncSecret(ctx, vClient, obj, nil)
	require.NoError(t, err)
	assert.False(t, updated)
	assert.Equal(t, &secretsv1beta1.VaultSecretLease{
		LeaseDuration: 0,
		Renewable:     false,
	}, lease)
	assert.Equal(t, int64(540), obj.Status.StaticCredsMetaData.TTL)
	assert.Equal(t, int64(600), obj.Status.StaticCredsMetaData.RotationPeriod)
	assert.Equal(t, time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC).Unix(), obj.Status.StaticCredsMetaData.LastVaultRotation)
	// Two requests: initial doVault + one backoff-loop doVault (inLastSyncRotation=true)
	assert.Equal(t, 2, len(vClient.Requests))
}

// TestVaultDynamicSecretReconciler_Reconcile_forceSyncStaticCredsUsesRefreshedTTL
// covers the scenario: a VaultAuth token expiry evicts the cacheKey and
// triggers a ForceSync via SyncRegistry, but no Vault rotation has occurred.
// Vault returns a lower TTL (time has passed) with the same LastVaultRotation.
// VSO must update status with the fresh TTL so that computePostSyncHorizon
// produces the correct RequeueAfter — not the stale horizon from the last sync.
//
// Covered behavior:
//   - Reconcile is triggered through SyncRegistry (force sync)
//   - the Vault client is obtained through ClientFactory and matches the
//     object's cached client metadata
//   - Vault returns a lower TTL but the same LastVaultRotation (no rotation)
//   - awaitVaultSecretRotation enters the backoff loop (inLastSyncRotation=true)
//     and makes a second Vault request, confirming the same stable state
//   - the destination Secret already contains the same data, so the secret
//     payload is not rewritten
//   - Reconcile persists the refreshed TTL from the latest Vault response
//   - computePostSyncHorizon uses the refreshed TTL for RequeueAfter
//   - the SyncRegistry entry is removed after a successful reconcile
//
// Previous status: TTL=600, LastVaultRotation=12:00
// Refreshed Vault metadata: TTL=540, LastVaultRotation=12:00
func TestVaultDynamicSecretReconciler_Reconcile_forceSyncStaticCredsUsesRefreshedTTL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	validator := &testHMACValidator{}
	secretData := map[string][]byte{
		"password": []byte("db-pass"),
		"username": []byte("db-user"),
	}
	message, err := json.Marshal(secretData)
	require.NoError(t, err)
	messageMAC, err := validator.HMAC(ctx, nil, message)
	require.NoError(t, err)

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
			SecretMAC:      base64.StdEncoding.EncodeToString(messageMAC),
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
		Data: secretData,
	}

	secretClient := testutils.NewFakeClientBuilder().
		WithStatusSubresource(obj).
		WithObjects(obj, destSecret).
		Build()

	freshResponse := &vaultResponse{
		secret: &api.Secret{},
		data: map[string]any{
			"last_vault_rotation": "2026-04-21T12:00:00Z",
			"rotation_period":     600,
			"ttl":                 540,
			"username":            "db-user",
			"password":            "db-pass",
		},
		k8s: secretData,
	}
	vClient := &reconcileTestVaultClient{
		MockRecordingVaultClient: &vault.MockRecordingVaultClient{
			Id: "client-1",
			ReadResponses: map[string][]vault.Response{
				// Two responses: one for the initial doVault call in syncSecret, one
				// for the doVault call inside the awaitVaultSecretRotation backoff
				// loop (triggered because inLastSyncRotation=true).
				"database/static-creds/app": {freshResponse, freshResponse},
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
		HMACValidator:               validator,
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
	assert.GreaterOrEqual(t, result.RequeueAfter, 540*time.Second+500*time.Millisecond)
	assert.LessOrEqual(t, result.RequeueAfter, 540*time.Second+650*time.Millisecond)

	updated := &secretsv1beta1.VaultDynamicSecret{}
	require.NoError(t, secretClient.Get(ctx, objKey, updated))
	assert.Equal(t, int64(540), updated.Status.StaticCredsMetaData.TTL)
	assert.Equal(t, int64(600), updated.Status.StaticCredsMetaData.RotationPeriod)
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
