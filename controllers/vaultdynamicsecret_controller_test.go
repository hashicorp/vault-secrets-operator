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

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/vault"
)

// Test helpers

func newVaultResponse(data map[string]any) *vaultResponse {
	return &vaultResponse{data: data}
}

func newStaticCredsResponse(lastRotation, password, username string, ttl, rotationPeriod int, rotationSchedule string) *vaultResponse {
	data := map[string]any{
		"last_vault_rotation": lastRotation,
		"password":            password,
		"username":            username,
		"ttl":                 ttl,
	}
	if rotationPeriod > 0 {
		data["rotation_period"] = rotationPeriod
	}
	if rotationSchedule != "" {
		data["rotation_schedule"] = rotationSchedule
		data["rotation_window"] = 3600
	}
	return newVaultResponse(data)
}

func assertInRange(t *testing.T, got, min, max time.Duration) {
	t.Helper()
	assert.GreaterOrEqual(t, got, min, "horizon below minimum")
	assert.LessOrEqual(t, got, max, "horizon above maximum")
}

func withPollingBudget(t *testing.T, maxElapsed, maxInterval time.Duration) {
	t.Helper()
	orig := rotationPeriodPollMaxElapsed
	origInterval := rotationPeriodPollMaxInterval
	rotationPeriodPollMaxElapsed = maxElapsed
	rotationPeriodPollMaxInterval = maxInterval
	t.Cleanup(func() {
		rotationPeriodPollMaxElapsed = orig
		rotationPeriodPollMaxInterval = origInterval
	})
}

func makeStuckRotationResponses(lastRotation, password, username string, n int) []vault.Response {
	responses := make([]vault.Response, n)
	for i := 0; i < n; i++ {
		responses[i] = newStaticCredsResponse(lastRotation, password, username, 0, 3600, "")
	}
	return responses
}

func newRotationPeriodVDS(mount, path string, lastRotation int64, period, ttl int) *secretsv1beta1.VaultDynamicSecret {
	return &secretsv1beta1.VaultDynamicSecret{
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount: mount,
			Path:  path,
		},
		Status: secretsv1beta1.VaultDynamicSecretStatus{
			StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: lastRotation,
				RotationPeriod:    int64(period),
				TTL:               int64(ttl),
			},
		},
	}
}

func assertRotationInProgressError(t assert.TestingT, err error) bool {
	var rotErr *RotationInProgressError
	return assert.ErrorAs(t, err, &rotErr)
}

func fakeRecorder() record.EventRecorder {
	return record.NewFakeRecorder(1024)
}

func Test_computeRelativeHorizon(t *testing.T) {
	now := nowFunc()
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
					LastRenewalTime: now.Unix() - 600,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Until(time.Unix(now.Unix()-600, 0).Add(
				computeStartRenewingAt(time.Second*600, 67))),
		},
		"two thirds elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 450,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(now.Unix()-450, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(now),
		},
		"one third elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 200,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(now.Unix()-200, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(now),
		},
		"past end of lease": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 800,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(now.Unix()-800, 0).Add(
				computeStartRenewingAt(time.Second*600, 67)).Sub(now),
		},
		"renewalPercent is 0": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 0,
				},
			},
			expectedInWindow: true,
			expectedHorizon: time.Unix(now.Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, 0)).Sub(now),
		},
		"renewalPercent is cap": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: renewalPercentCap,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(now.Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, renewalPercentCap)).Sub(now),
		},
		"renewalPercent exceeds cap": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: now.Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: renewalPercentCap + 1,
				},
			},
			expectedInWindow: false,
			expectedHorizon: time.Unix(now.Unix()-400, 0).Add(
				computeStartRenewingAt(time.Second*600, renewalPercentCap+1)).Sub(now),
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
		metaData *secretsv1beta1.VaultStaticCredsMetaData
		want     bool
	}{
		{
			name: "static-cred-with-rotation-period",
			metaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1695430611,
				RotationPeriod:    300,
			},
			want: true,
		},
		{
			name: "not-static-cred-with-rotation-period",
			metaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 0,
				RotationPeriod:    0,
			},
			want: false,
		},
		{
			name: "static-cred-with-rotation-schedule",
			metaData: &secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: 1695430611,
				RotationSchedule:  "1 0 * * *",
			},
			want: true,
		},
		{
			name: "not-static-cred-with-rotation-schedule",
			metaData: &secretsv1beta1.VaultStaticCredsMetaData{
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
	now := time.Unix(nowFunc().Unix(), 0)
	defaultNowFunc := func() time.Time { return now }

	tests := []struct {
		name           string
		o              *secretsv1beta1.VaultDynamicSecret
		minHorizon     time.Duration
		wantMinHorizon time.Duration
		wantMaxHorizon time.Duration
		wantInWindow   bool
	}{
		{
			name: "static-creds-in-rotation-window-after-sync",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: now.Unix(),
						TTL:               30,
					},
				},
			},
			wantMinHorizon: 30 * time.Second,
			wantMaxHorizon: 30*time.Second + staticCredsJitterHorizon,
			wantInWindow:   true,
		},
		{
			name: "static-creds-in-rotation-window-by-1s",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						TTL:               30,
						LastVaultRotation: now.Unix() - 29,
					},
				},
			},
			minHorizon:     1 * time.Second,
			wantMinHorizon: 1 * time.Second,
			wantMaxHorizon: time.Duration(1.2 * float64(time.Second)),
			wantInWindow:   true,
		},
		{
			name: "static-creds-not-in-rotation-window",
			o: &secretsv1beta1.VaultDynamicSecret{
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					AllowStaticCreds: true,
				},
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						TTL:               30,
						LastVaultRotation: now.Unix() - 30,
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
					LastRenewalTime: now.Unix(),
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
					LastRenewalTime: now.Unix() - 90,
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
			nowFuncOrig := nowFunc
			t.Cleanup(func() {
				nowFunc = nowFuncOrig
			})
			nowFunc = defaultNowFunc
			gotHorizon, gotInWindow := computeRelativeHorizonWithJitter(tt.o, tt.minHorizon)
			assert.Equal(t, tt.wantInWindow, gotInWindow)
			assertInRange(t, gotHorizon, tt.wantMinHorizon, tt.wantMaxHorizon)
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
			r := &VaultDynamicSecretReconciler{}
			got := r.computePostSyncHorizon(ctx, tt.o)
			assertInRange(t, got, tt.wantMinHorizon, tt.wantMaxHorizon)
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
			got, err := vaultStaticCredsMetaDataFromData(tt.data)
			if !tt.wantErr(t, err, fmt.Sprintf("vaultStaticCredsMetaDataFromData(%v)", tt.data)) {
				return
			}
			assert.Equalf(t, tt.want, got, "vaultStaticCredsMetaDataFromData(%v)", tt.data)
		})
	}
}

type vaultResponse struct {
	data map[string]any
}

func (s *vaultResponse) WrapInfo() *api.SecretWrapInfo {
	return nil
}

func (s *vaultResponse) Secret() *api.Secret {
	return &api.Secret{
		Data: s.data,
	}
}

func (s *vaultResponse) Data() map[string]any {
	return s.data
}

func (s *vaultResponse) SecretK8sData(_ *helpers.SecretTransformationOption) (map[string][]byte, error) {
	return nil, nil
}

func TestVaultDynamicSecretReconciler_awaitRotation(t *testing.T) {
	ts, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:48:01.328261545Z")
	require.NoError(t, err)

	ts1, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:49:01.325799425Z")
	require.NoError(t, err)

	tsStr := "2024-05-02T19:48:01.328261545Z"
	ts1Str := "2024-05-02T19:49:01.325799425Z"

	ctx := context.Background()
	withPollingBudget(t, 200*time.Millisecond, 10*time.Millisecond)
	tests := []struct {
		name                    string
		o                       *secretsv1beta1.VaultDynamicSecret
		c                       *vault.MockRecordingVaultClient
		initialResponse         vault.Response
		wantStaticCredsMetaData *secretsv1beta1.VaultStaticCredsMetaData
		wantResponse            vault.Response
		assertRequestCount      bool
		expectedRequestCount    int
		wantErr                 assert.ErrorAssertionFunc
	}{
		// Error cases
		{
			name:            "invalid-static-creds-meta-data",
			c:               &vault.MockRecordingVaultClient{},
			o:               &secretsv1beta1.VaultDynamicSecret{},
			initialResponse: newStaticCredsResponse("2-024-05-02T19:48:01.328261545Z", "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-scheduled", 59, 0, "*/1 * * * *"),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "invalid last_vault_rotation", i...)
			},
		},
		// Non-static creds
		{
			name:                    "not-static-creds",
			c:                       &vault.MockRecordingVaultClient{},
			initialResponse:         newVaultResponse(map[string]any{"username": "foo", "password": "bar"}),
			wantErr:                 assert.NoError,
			wantResponse:            newVaultResponse(map[string]any{"username": "foo", "password": "bar"}),
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{},
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
		// Static creds with rotation_schedule (no TTL<=2 polling)
		{
			name:            "empty-last-rotation-schedule",
			c:               &vault.MockRecordingVaultClient{},
			initialResponse: newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-scheduled", 59, 0, "*/1 * * * *"),
			wantErr:         assert.NoError,
			o: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts.Unix(),
						TTL:               55,
					},
				},
			},
			wantResponse:            newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-scheduled", 59, 0, "*/1 * * * *"),
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationSchedule: "*/1 * * * *", TTL: 59},
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
		{
			name:            "static-creds-periodic-rotation",
			c:               &vault.MockRecordingVaultClient{},
			initialResponse: newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-xxx", 59, 3600, ""),
			wantErr:         assert.NoError,
			o: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
						LastVaultRotation: ts.Unix(),
						TTL:               55,
					},
				},
			},
			wantResponse:            newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-xxx", 59, 3600, ""),
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationPeriod: 3600, TTL: 59},
			assertRequestCount:      true,
			expectedRequestCount:    0,
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
						LastVaultRotation: ts.Unix(),
						RotationSchedule:  "*/1 * * * *",
						TTL:               55,
					},
				},
			},
			initialResponse:         newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-scheduled", 0, 0, "*/1 * * * *"),
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts1.Unix(), RotationSchedule: "*/1 * * * *", TTL: 58},
			wantResponse:            newStaticCredsResponse(ts1Str, "qSGA-u8f1-H6WYkII4Yn", "dev-postgres-static-user-scheduled", 58, 0, "*/1 * * * *"),
			c: &vault.MockRecordingVaultClient{
				ReadResponses: map[string][]vault.Response{
					"mount/static-creds/scheduled": {
						newStaticCredsResponse(tsStr, "Y3pro72-fl1ndHTFOg9h", "dev-postgres-static-user-scheduled", 59, 0, "*/1 * * * *"),
						newStaticCredsResponse(ts1Str, "qSGA-u8f1-H6WYkII4Yn", "dev-postgres-static-user-scheduled", 58, 0, "*/1 * * * *"),
					},
				},
			},
			assertRequestCount:   true,
			expectedRequestCount: 2,
		},
		// rotation_period + TTL<=2 workaround (PR #1217)
		{
			name:            "rotation-period-success",
			o:               newRotationPeriodVDS("database", "static-creds/rotation-period-role", ts.Unix(), 3600, 55),
			initialResponse: newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
			c: &vault.MockRecordingVaultClient{
				ReadResponses: map[string][]vault.Response{
					"database/static-creds/rotation-period-role": {
						newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 3599, 3600, ""),
					},
				},
			},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts1.Unix(), RotationPeriod: 3600, TTL: 3599},
			wantResponse:            newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 3599, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    1,
		},
		{
			name:            "rotation-period-timeout",
			o:               newRotationPeriodVDS("database", "static-creds/stuck-rotation", ts.Unix(), 3600, 55),
			initialResponse: newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
			c: &vault.MockRecordingVaultClient{
				ReadResponses: map[string][]vault.Response{
					"database/static-creds/stuck-rotation": makeStuckRotationResponses(tsStr, "old-password", "dev-postgres-static-user", 5),
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assertRotationInProgressError(t, err)
			},
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationPeriod: 3600, TTL: 0},
			wantResponse:            newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
			assertRequestCount:      false,
		},
		{
			name:                    "rotation-period-no-retry",
			o:                       newRotationPeriodVDS("database", "static-creds/normal", ts.Unix(), 3600, 55),
			initialResponse:         newStaticCredsResponse(tsStr, "current-password", "dev-postgres-static-user", 3500, 3600, ""),
			c:                       &vault.MockRecordingVaultClient{},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationPeriod: 3600, TTL: 3500},
			wantResponse:            newStaticCredsResponse(tsStr, "current-password", "dev-postgres-static-user", 3500, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
		{
			name:                    "rotation-period-already-rotated",
			o:                       newRotationPeriodVDS("database", "static-creds/already-rotated", ts.Unix(), 3600, 55),
			initialResponse:         newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 0, 3600, ""),
			c:                       &vault.MockRecordingVaultClient{},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts1.Unix(), RotationPeriod: 3600, TTL: 0},
			wantResponse:            newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 0, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
		{
			name:                    "rotation-period-first-sync",
			o:                       newRotationPeriodVDS("database", "static-creds/first-sync", 0, 3600, 0),
			initialResponse:         newStaticCredsResponse(tsStr, "initial-password", "dev-postgres-static-user", 0, 3600, ""),
			c:                       &vault.MockRecordingVaultClient{},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationPeriod: 3600, TTL: 0},
			wantResponse:            newStaticCredsResponse(tsStr, "initial-password", "dev-postgres-static-user", 0, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
		// TTL boundary cases: ttl<=2 triggers polling, ttl>2 does not
		{
			name:            "rotation-period-ttl-2-retry",
			o:               newRotationPeriodVDS("database", "static-creds/ttl-2-role", ts.Unix(), 3600, 55),
			initialResponse: newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 2, 3600, ""),
			c: &vault.MockRecordingVaultClient{
				ReadResponses: map[string][]vault.Response{
					"database/static-creds/ttl-2-role": {
						newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 3599, 3600, ""),
					},
				},
			},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts1.Unix(), RotationPeriod: 3600, TTL: 3599},
			wantResponse:            newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 3599, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    1,
		},
		{
			name:                    "rotation-period-ttl-3-no-retry",
			o:                       newRotationPeriodVDS("database", "static-creds/ttl-3-role", ts.Unix(), 3600, 55),
			initialResponse:         newStaticCredsResponse(tsStr, "current-password", "dev-postgres-static-user", 3, 3600, ""),
			c:                       &vault.MockRecordingVaultClient{},
			wantErr:                 assert.NoError,
			wantStaticCredsMetaData: &secretsv1beta1.VaultStaticCredsMetaData{LastVaultRotation: ts.Unix(), RotationPeriod: 3600, TTL: 3},
			wantResponse:            newStaticCredsResponse(tsStr, "current-password", "dev-postgres-static-user", 3, 3600, ""),
			assertRequestCount:      true,
			expectedRequestCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &VaultDynamicSecretReconciler{}
			got, got1, err := r.awaitVaultSecretRotation(ctx, tt.o, tt.c, tt.initialResponse)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.wantStaticCredsMetaData, got)
			assert.Equal(t, tt.wantResponse, got1)
			if tt.assertRequestCount {
				assert.Equal(t, tt.expectedRequestCount, len(tt.c.Requests))
			}
		})
	}
}

// TestVaultDynamicSecretReconciler_awaitRotation_RotationPeriodPolling_WaitForAdvance tests that awaitVaultSecretRotation
// successfully polls Vault when rotation_period mode encounters ttl<=2, waiting for last_vault_rotation to advance.
// This implements PR #1217 workaround: when TTL<=2 is detected for rotation_period static creds,
// the reconciler polls with short backoff until the rotation completes (LVR changes).
func TestVaultDynamicSecretReconciler_awaitRotation_RotationPeriodPolling_WaitForAdvance(t *testing.T) {
	ts, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:48:01.328261545Z")
	require.NoError(t, err)
	ts1, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:49:01.325799425Z")
	require.NoError(t, err)

	tsStr := "2024-05-02T19:48:01.328261545Z"
	ts1Str := "2024-05-02T19:49:01.325799425Z"

	ctx := context.Background()
	withPollingBudget(t, 2*time.Second, 100*time.Millisecond)

	// Setup: VaultDynamicSecret in rotation_period mode (no rotation_schedule).
	// Initial response has ttl=0 with LVR=ts.Unix(), simulating rotation in progress.
	o := newRotationPeriodVDS("database", "static-creds/rotation-period-role", ts.Unix(), 3600, 55)
	initialResponse := newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, "")

	// Mock Vault client returns a sequence of stuck responses followed by advanced response.
	// This proves polling actually occurs (multiple read attempts) before rotation completes.
	c := &vault.MockRecordingVaultClient{
		ReadResponses: map[string][]vault.Response{
			"database/static-creds/rotation-period-role": {
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 2, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 1, 3600, ""),
				newStaticCredsResponse(ts1Str, "new-password", "dev-postgres-static-user", 3599, 3600, ""),
			},
		},
	}

	r := &VaultDynamicSecretReconciler{}
	staticMeta, finalResp, err := r.awaitVaultSecretRotation(ctx, o, c, initialResponse)

	// Assertions
	require.NoError(t, err, "expected polling to succeed when LVR advances")
	assert.Equal(t, ts1.Unix(), staticMeta.LastVaultRotation, "expected LastVaultRotation to advance after polling")
	assert.Equal(t, int64(3599), staticMeta.TTL, "expected updated TTL after rotation completes")

	finalData := finalResp.Data()
	assert.Equal(t, "new-password", finalData["password"], "expected new password after rotation")
	assert.GreaterOrEqual(t, len(c.Requests), 2, "expected multiple read attempts during polling to prove polling occurred")
}

// TestVaultDynamicSecretReconciler_awaitRotation_RotationPeriodTimeout tests that awaitVaultSecretRotation
// returns RotationInProgressError when polling times out waiting for last_vault_rotation to advance.
// This implements PR #1217 timeout handling: when polling doesn't see LVR change within the timeout window,
// awaitVaultSecretRotation returns RotationInProgressError for special handling in Reconcile.
func TestVaultDynamicSecretReconciler_awaitRotation_RotationPeriodTimeout(t *testing.T) {
	ts, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:48:01.328261545Z")
	require.NoError(t, err)
	tsStr := "2024-05-02T19:48:01.328261545Z"

	ctx := context.Background()
	withPollingBudget(t, 100*time.Millisecond, 10*time.Millisecond)

	// Setup: VaultDynamicSecret in rotation_period mode with stuck rotation.
	o := newRotationPeriodVDS("database", "static-creds/stuck-rotation", ts.Unix(), 3600, 55)
	initialResponse := newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, "")

	// Mock Vault client returns multiple stuck responses: LVR never advances, ttl stays at 0.
	// Provide enough responses to allow multiple polling attempts before timeout.
	c := &vault.MockRecordingVaultClient{
		ReadResponses: map[string][]vault.Response{
			"database/static-creds/stuck-rotation": makeStuckRotationResponses(tsStr, "old-password", "dev-postgres-static-user", 50),
		},
	}

	r := &VaultDynamicSecretReconciler{}
	staticMeta, _, err := r.awaitVaultSecretRotation(ctx, o, c, initialResponse)

	// Assertions
	var rotErr *RotationInProgressError
	require.ErrorAs(t, err, &rotErr, "expected RotationInProgressError when polling times out")
	assert.Equal(t, ts.Unix(), staticMeta.LastVaultRotation, "expected LastVaultRotation unchanged (rotation did not complete)")
	assert.Equal(t, int64(0), staticMeta.TTL, "expected TTL unchanged from stuck rotation")
}

// TestVaultDynamicSecretReconciler_Reconcile_RotationInProgressError_RequeuesQuickly_AndDoesNotWriteSecret tests
// that Reconcile handles RotationInProgressError specially:
// - Returns nil error with RequeueAfter computed from BackOffRegistry (exponential backoff, not fixed delay)
// - Does NOT create/update the destination Secret
// - Exercises full Vault polling when rotation_period TTL is low
// This implements PR #1217 Reconcile-level behavior for stuck rotations.
func TestVaultDynamicSecretReconciler_Reconcile_RotationInProgressError_RequeuesQuickly_AndDoesNotWriteSecret(t *testing.T) {
	ts, err := time.Parse(time.RFC3339Nano, "2024-05-02T19:48:01.328261545Z")
	require.NoError(t, err)
	tsStr := "2024-05-02T19:48:01.328261545Z"

	ctx := context.Background()
	withPollingBudget(t, 100*time.Millisecond, 10*time.Millisecond)

	// Create a minimal VaultAuth object with proper kubernetes auth config
	vaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-auth",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: consts.ProviderMethodKubernetes,
			Mount:  "kubernetes",
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           "test-role",
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	}

	// Create VaultDynamicSecret in rotation_period mode with destination Secret
	o := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rotation-stuck",
			Namespace: "default",
		},
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Mount:            "database",
			Path:             "static-creds/stuck-role",
			VaultAuthRef:     "test-auth",
			AllowStaticCreds: true,
			Destination: secretsv1beta1.Destination{
				Name:   "rotation-stuck-secret",
				Create: true,
			},
		},
		Status: secretsv1beta1.VaultDynamicSecretStatus{
			StaticCredsMetaData: secretsv1beta1.VaultStaticCredsMetaData{
				LastVaultRotation: ts.Unix(),
				RotationPeriod:    3600,
				RotationSchedule:  "",
				TTL:               55,
			},
		},
	}

	// Create fake k8s client and add the VaultDynamicSecret and VaultAuth
	k8sClient := testutils.NewFakeClient()
	require.NoError(t, k8sClient.Create(ctx, vaultAuth))
	require.NoError(t, k8sClient.Create(ctx, o))

	// Create mock Vault client that will timeout: stuck responses never advance LVR
	// The initial read returns ttl=0 to trigger polling in awaitVaultSecretRotation.
	// Subsequent reads (during polling) return stuck responses that don't advance LVR.
	mockVaultClient := &vault.MockRecordingVaultClient{
		ReadResponses: map[string][]vault.Response{
			"database/static-creds/stuck-role": {
				// Initial read: ttl <= 2 will trigger polling
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				// Polling reads: return stuck responses that don't advance LVR
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				// More responses in case of additional retries
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
				newStaticCredsResponse(tsStr, "old-password", "dev-postgres-static-user", 0, 3600, ""),
			},
		},
	}

	// Create a mock ClientFactory that returns our mock Vault client
	mockClientFactory := &testClientFactory{
		client: &testVaultClient{MockRecordingVaultClient: mockVaultClient},
	}

	// Create BackOffRegistry with deterministic options (no randomization)
	// This ensures RequeueAfter == InitialInterval on first call
	backOffRegistry := NewBackOffRegistry(
		backoff.WithInitialInterval(5*time.Second),
		backoff.WithMaxInterval(60*time.Second),
		backoff.WithRandomizationFactor(0),
		backoff.WithMultiplier(2),
	)
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "rotation-stuck", Namespace: "default"},
	}

	// Create a reconciler with the fake k8s client and mock ClientFactory
	r := &VaultDynamicSecretReconciler{
		Client:          k8sClient,
		ClientFactory:   mockClientFactory,
		referenceCache:  NewResourceReferenceCache(),
		SyncRegistry:    NewSyncRegistry(),
		BackOffRegistry: backOffRegistry,
		Recorder:        fakeRecorder(),
	}

	// Call Reconcile with the stuck rotation resource
	res, err := r.Reconcile(ctx, req)

	// Assertions
	// 1. Reconcile returns nil error (RotationInProgressError is handled internally)
	require.NoError(t, err, "expected Reconcile to handle RotationInProgressError and return nil error")

	// 2. Result has the deterministic BackOffRegistry initial interval (5 seconds)
	assert.Equal(t, 5*time.Second, res.RequeueAfter, "expected RequeueAfter == InitialInterval with zero randomization")

	// 3. Destination Secret was NOT created
	destSecretKey := types.NamespacedName{Name: "rotation-stuck-secret", Namespace: "default"}
	destSecret := &corev1.Secret{}
	err = k8sClient.Get(ctx, destSecretKey, destSecret)
	assert.Error(t, err, "expected destination Secret NOT to be created when rotation is stuck")
	assert.True(t, apierrors.IsNotFound(err), "expected NotFound error")

	// 4. Resource status remains unchanged (rotation did not complete)
	updated := &secretsv1beta1.VaultDynamicSecret{}
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "rotation-stuck", Namespace: "default"}, updated))
	assert.Equal(t, ts.Unix(), updated.Status.StaticCredsMetaData.LastVaultRotation, "expected LastVaultRotation unchanged")

	// 5. Prove polling actually occurred: multiple Vault reads to the expected path
	assert.GreaterOrEqual(t, len(mockVaultClient.Requests), 2, "expected multiple Vault reads due to rotation-period polling")
	assert.Equal(t, http.MethodGet, mockVaultClient.Requests[0].Method, "expected first request to be GET")
	assert.Equal(t, "database/static-creds/stuck-role", mockVaultClient.Requests[0].Path, "expected request path to be the database secret path")
	// Verify all requests are to the same path (no unexpected calls)
	for i, req := range mockVaultClient.Requests {
		assert.Equalf(t, "database/static-creds/stuck-role", req.Path, "request %d: expected all paths to match", i)
	}

	// 6. Verify side effects: object added to SyncRegistry and BackOffRegistry has the entry
	assert.True(t, r.SyncRegistry.Has(req.NamespacedName), "expected object to be in SyncRegistry after RotationInProgressError")
	entry, created := r.BackOffRegistry.Get(req.NamespacedName)
	assert.False(t, created, "expected BackOffRegistry entry to already exist after Reconcile")
	assert.NotNil(t, entry, "expected BackOffRegistry to have entry for the object")
}

// testClientFactory is a test stub that implements vault.ClientFactory
type testClientFactory struct {
	client vault.Client
}

func (f *testClientFactory) Get(context.Context, client.Client, client.Object) (vault.Client, error) {
	return f.client, nil
}

func (f *testClientFactory) RegisterClientCallbackHandler(vault.ClientCallbackHandler) {
	// no-op for tests
}

// testVaultClient wraps MockRecordingVaultClient to implement the full vault.Client interface for testing
type testVaultClient struct {
	*vault.MockRecordingVaultClient
}

func (c *testVaultClient) Init(context.Context, client.Client, *secretsv1beta1.VaultAuth, *secretsv1beta1.VaultConnection, string, *vault.ClientOptions) error {
	return nil
}

func (c *testVaultClient) Login(context.Context, client.Client) error {
	return nil
}

func (c *testVaultClient) Restore(context.Context, *api.Secret) error {
	return nil
}

func (c *testVaultClient) GetTokenSecret() *api.Secret {
	return nil
}

func (c *testVaultClient) CheckExpiry(int64) (bool, error) {
	return false, nil
}

func (c *testVaultClient) Validate(context.Context) error {
	return nil
}

func (c *testVaultClient) GetVaultAuthObj() *secretsv1beta1.VaultAuth {
	return nil
}

func (c *testVaultClient) GetVaultConnectionObj() *secretsv1beta1.VaultConnection {
	return nil
}

func (c *testVaultClient) GetCredentialProvider() provider.CredentialProviderBase {
	return nil
}

func (c *testVaultClient) GetCacheKey() (vault.ClientCacheKey, error) {
	return "test-cache-key", nil
}

func (c *testVaultClient) Close(bool) {
	// no-op
}

func (c *testVaultClient) Clone(string) (vault.Client, error) {
	return c, nil
}

func (c *testVaultClient) IsClone() bool {
	return false
}

func (c *testVaultClient) Namespace() string {
	return ""
}

func (c *testVaultClient) SetNamespace(string) {
	// no-op
}

func (c *testVaultClient) Tainted() bool {
	return false
}

func (c *testVaultClient) Untaint() bool {
	return true
}

func (c *testVaultClient) WebsocketClient(string) (*vault.WebsocketClient, error) {
	return nil, nil
}

func (c *testVaultClient) Renewable() bool {
	return true
}
