// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
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
			wantMaxHorizon: time.Duration(1 * time.Second),
			wantInWindow:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			wantMinHorizon: time.Duration(30.5 * float64(time.Second)),
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
	t.Parallel()

	builder := newClientBuilder()
	// instances in the same namespace that should be included by the callback.
	instances := []*secretsv1beta1.VaultDynamicSecret{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "baz",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: "kubernetes-12345",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "canary",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: "kubernetes-54321",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "other",
				Name:      "canary-other-ns",
			},
			Status: secretsv1beta1.VaultDynamicSecretStatus{
				VaultClientMeta: secretsv1beta1.VaultClientMeta{
					CacheKey: "kubernetes-12345",
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
				cacheKey:           "kubernetes-12345",
				credentialProvider: &stubCredentialProvider{namespace: "default"},
			},
			want: []any{
				reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "baz",
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
			syncRegistry := NewSyncRegistry()
			r := &VaultDynamicSecretReconciler{
				Client:       builder.Build(),
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

			cs := &source.Channel{
				Source: r.SourceCh,
			}

			handler := &enqueueDelayingSyncEventHandler{
				enqueueDurationForJitter: time.Second * 2,
			}

			q := &DelegatingQueue{
				Interface: workqueue.New(),
			}

			go func() {
				err := cs.Start(ctx, handler, q)
				require.NoError(t, err, "cs.Start")
			}()

			r.vaultClientCallback(ctx, tt.c)
			assert.Eventuallyf(t, func() bool {
				return len(q.AddedAfter) == len(tt.want)
			}, handler.enqueueDurationForJitter, time.Millisecond*100,
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
