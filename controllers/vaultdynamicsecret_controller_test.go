// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

func Test_inRenewalWindow(t *testing.T) {
	tests := map[string]struct {
		vds              *secretsv1beta1.VaultDynamicSecret
		expectedInWindow bool
	}{
		"full lease elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 600,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"two thirds elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 450,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"one third elapsed": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 200,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: false,
		},
		"past end of lease": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 800,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 67,
				},
			},
			expectedInWindow: true,
		},
		"renewalPercent is 0": {
			vds: &secretsv1beta1.VaultDynamicSecret{
				Status: secretsv1beta1.VaultDynamicSecretStatus{
					SecretLease: secretsv1beta1.VaultSecretLease{
						LeaseDuration: 600,
					},
					LastRenewalTime: time.Now().Unix() - 400,
				},
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					RenewalPercent: 0,
				},
			},
			expectedInWindow: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expectedInWindow, inRenewalWindow(tc.vds))
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
			got, _, err := r.syncSecret(tt.args.ctx, tt.args.vClient, tt.args.o)
			if !tt.wantErr(t, err, fmt.Sprintf("syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)) {
				return
			}
			assert.Equalf(t, tt.want, got, "syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)
			assert.Equalf(t, tt.expectRequests, tt.args.vClient.Requests, "syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)
		})
	}
}

func TestVaultDynamicSecretReconciler_syncSecret_staticCreds(t *testing.T) {
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
						AllowStaticCreds: true,
					},
					Status: secretsv1beta1.VaultDynamicSecretStatus{
						StaticCredsMetaData: v1beta1.VaultStaticCredsMetaData{
							LastVaultRotation: 1695419440,
							RotationSchedule:  "1 0 * * *",
						},
						SecretMAC: "vso-cc-storage-hmac-key",
					},
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
		// {
		// 	name: "with-params",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount: "baz",
		// 				Path:  "foo",
		// 				Params: map[string]string{
		// 					"qux": "bar",
		// 				},
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: map[string]any{
		// 				"qux": "bar",
		// 			},
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "with-method-put-and-params",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodPut,
		// 				Params: map[string]string{
		// 					"qux": "bar",
		// 				},
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: map[string]any{
		// 				"qux": "bar",
		// 			},
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "with-method-post-and-params",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodPost,
		// 				Params: map[string]string{
		// 					"qux": "bar",
		// 				},
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			// the vault client API always translates POST to PUT
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: map[string]any{
		// 				"qux": "bar",
		// 			},
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "with-method-get-and-params",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodGet,
		// 				Params: map[string]string{
		// 					"qux": "bar",
		// 				},
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: map[string]any{
		// 				"qux": "bar",
		// 			},
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "without-params-and-method-get",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodGet,
		// 				Params:            nil,
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			Method: http.MethodGet,
		// 			Path:   "baz/foo",
		// 			Params: nil,
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "without-params-and-method-put",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodPut,
		// 				Params:            nil,
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: nil,
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "without-params-and-method-post",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodPost,
		// 				Params:            nil,
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want: &secretsv1beta1.VaultSecretLease{
		// 		LeaseDuration: 0,
		// 		Renewable:     false,
		// 	},
		// 	expectRequests: []*vault.MockRequest{
		// 		{
		// 			// the vault client API always translates POST to PUT
		// 			Method: http.MethodPut,
		// 			Path:   "baz/foo",
		// 			Params: nil,
		// 		},
		// 	},
		// 	wantErr: assert.NoError,
		// },
		// {
		// 	name: "with-unsupported-method",
		// 	fields: fields{
		// 		Client:        fake.NewClientBuilder().Build(),
		// 		runtimePodUID: "",
		// 	},
		// 	args: args{
		// 		ctx:     nil,
		// 		vClient: &vault.MockRecordingVaultClient{},
		// 		o: &secretsv1beta1.VaultDynamicSecret{
		// 			ObjectMeta: metav1.ObjectMeta{
		// 				Name:      "baz",
		// 				Namespace: "default",
		// 			},
		// 			Spec: secretsv1beta1.VaultDynamicSecretSpec{
		// 				Mount:             "baz",
		// 				Path:              "foo",
		// 				RequestHTTPMethod: http.MethodOptions,
		// 				Params:            nil,
		// 				Destination: secretsv1beta1.Destination{
		// 					Name:   "baz",
		// 					Create: true,
		// 				},
		// 			},
		// 			Status: secretsv1beta1.VaultDynamicSecretStatus{},
		// 		},
		// 	},
		// 	want:           nil,
		// 	expectRequests: nil,
		// 	wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
		// 		return assert.EqualError(t, err, fmt.Sprintf(
		// 			"unsupported HTTP method %q for sync", http.MethodOptions), i...)
		// 	},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := helpers.NewHMACValidator(vault.DefaultClientCacheStorageConfig().HMACSecretObjKey)
			r := &VaultDynamicSecretReconciler{
				Client:        tt.fields.Client,
				HMACValidator: validator,
			}
			got, _, err := r.syncSecret(tt.args.ctx, tt.args.vClient, tt.args.o)
			if !tt.wantErr(t, err, fmt.Sprintf("syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)) {
				return
			}
			assert.Equalf(t, tt.want, got, "syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)
			assert.Equalf(t, tt.expectRequests, tt.args.vClient.Requests, "syncSecret(%v, %v, %v)", tt.args.ctx, tt.args.vClient, tt.args.o)
		})
	}
}

type mockRequest struct {
	method string
	path   string
	params map[string]any
}
