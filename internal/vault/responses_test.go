// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

type testResponseSecret struct {
	name     string
	secret   *api.Secret
	want     *api.Secret
	respFunc func(tt testResponseSecret) Response
}

type testResponseData struct {
	name     string
	respFunc func(tt testResponseData) Response
	secret   *api.Secret
	want     map[string]interface{}
}

type testResponseSecretK8sData struct {
	name     string
	respFunc func(tt testResponseSecretK8sData) Response
	secret   *api.Secret
	opt      *helpers.SecretTransformationOption
	want     map[string][]byte
	wantErr  assert.ErrorAssertionFunc
}

func Test_defaultResponse_Data(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseData) Response {
		return &defaultResponse{
			secret: tt.secret,
		}
	}
	tests := []testResponseData{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: map[string]interface{}{
				"data": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
		{
			name:     "nil-data",
			respFunc: respFunc,
			secret:   &api.Secret{},
			want:     nil,
		},
		{
			name:     "nil-secret",
			respFunc: respFunc,
			secret:   nil,
			want:     nil,
		},
		{
			name:     "mismatched-data-structure",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			want: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseData(t, tt)
		})
	}
}

func Test_defaultResponse_Secret(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecret) Response {
		return &defaultResponse{
			secret: tt.secret,
		}
	}
	tests := []testResponseSecret{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
		},
		{
			name:     "nil-secret",
			secret:   nil,
			respFunc: respFunc,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecret(t, tt)
		})
	}
}

func Test_defaultResponse_SecretK8sData(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecretK8sData) Response {
		return &defaultResponse{
			secret: tt.secret,
		}
	}

	tests := []testResponseSecretK8sData{
		{
			name:     "basic",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": "qux",
				},
			},
			want: map[string][]byte{
				"baz":                    []byte("qux"),
				helpers.SecretDataKeyRaw: []byte(`{"baz":"qux"}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "invalid-empty-raw-data",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					helpers.SecretDataKeyRaw: "qux",
					"baz":                    "foo",
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, helpers.SecretDataErrorContainsRaw)
			},
		},
		{
			name:     "nil-data",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: nil,
			},
			want:    map[string][]byte{helpers.SecretDataKeyRaw: []byte(`null`)},
			wantErr: assert.NoError,
		},
		{
			name:     "invalid-raw-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": make(chan int),
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name:     "invalid-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"baz": make(chan int),
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecretK8sData(t, tt)
		})
	}
}

func Test_kvV1Response_Data(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseData) Response {
		return &kvV1Response{
			secret: tt.secret,
		}
	}
	tests := []testResponseData{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: map[string]interface{}{
				"data": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
		{
			name:     "nil-data",
			respFunc: respFunc,
			secret:   &api.Secret{},
			want:     nil,
		},
		{
			name:     "nil-secret",
			respFunc: respFunc,
			secret:   nil,
			want:     nil,
		},
		{
			name:     "mismatched-data-structure",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			want: map[string]interface{}{
				"foo": map[string]interface{}{
					"bar": "baz",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseData(t, tt)
		})
	}
}

func Test_kvV1Response_Secret(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecret) Response {
		return &kvV1Response{
			secret: tt.secret,
		}
	}
	tests := []testResponseSecret{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
		},
		{
			name:     "nil-secret",
			secret:   nil,
			respFunc: respFunc,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecret(t, tt)
		})
	}
}

func Test_kvV1Response_SecretK8sData(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecretK8sData) Response {
		return &kvV1Response{
			secret: tt.secret,
		}
	}

	tests := []testResponseSecretK8sData{
		{
			name:     "basic",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": "qux",
				},
			},
			want: map[string][]byte{
				"baz":                    []byte("qux"),
				helpers.SecretDataKeyRaw: []byte(`{"baz":"qux"}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "basic-templated",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": "qux",
				},
			},
			opt: &helpers.SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"tmpl1": {
						KeyOverride: "foo",
						Text: `{{- $key := "baz" -}}
{{- printf "ENV_%s=%s" ( $key | upper ) ( get .Secrets $key ) -}}`,
					},
				},
			},
			want: map[string][]byte{
				"baz":                    []byte("qux"),
				"foo":                    []byte("ENV_BAZ=qux"),
				helpers.SecretDataKeyRaw: []byte(`{"baz":"qux"}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "invalid-data-contains-raw",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					helpers.SecretDataKeyRaw: "qux",
					"baz":                    "foo",
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, helpers.SecretDataErrorContainsRaw)
			},
		},
		{
			name:     "invalid-empty-raw-data",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: nil,
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "raw portion of vault KV secret was nil")
			},
		},
		{
			name:     "invalid-raw-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": make(chan int),
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name:     "invalid-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"baz": make(chan int),
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecretK8sData(t, tt)
		})
	}
}

func Test_kvV2Response_Data(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseData) Response {
		return &kvV2Response{
			secret: tt.secret,
		}
	}
	tests := []testResponseData{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: map[string]interface{}{
				"bar": "baz",
			},
		},
		{
			name:     "nil-data",
			secret:   &api.Secret{},
			respFunc: respFunc,
			want:     nil,
		},
		{
			name:     "nil-secret",
			secret:   nil,
			respFunc: respFunc,
			want:     nil,
		},
		{
			name: "mismatched-data-structure",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"foo": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseData(t, tt)
		})
	}
}

func Test_kvV2Response_Secret(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecret) Response {
		return &kvV2Response{
			secret: tt.secret,
		}
	}
	tests := []testResponseSecret{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
			respFunc: respFunc,
			want: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
			},
		},
		{
			name:     "nil-secret",
			secret:   nil,
			respFunc: respFunc,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecret(t, tt)
		})
	}
}

func Test_kvV2Response_SecretK8sData(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseSecretK8sData) Response {
		return &kvV2Response{
			secret: tt.secret,
		}
	}

	tests := []testResponseSecretK8sData{
		{
			name:     "basic",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"baz": "qux",
					},
				},
			},
			want: map[string][]byte{
				"baz":                    []byte("qux"),
				helpers.SecretDataKeyRaw: []byte(`{"data":{"baz":"qux"}}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "basic-templated",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"baz": "qux",
					},
				},
			},
			opt: &helpers.SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"tmpl1": {
						KeyOverride: "foo",
						Text: `{{- $key := "baz" -}}
{{- printf "ENV_%s=%s" ( $key | upper ) ( get .Secrets $key ) -}}`,
					},
				},
			},
			want: map[string][]byte{
				"baz":                    []byte("qux"),
				"foo":                    []byte("ENV_BAZ=qux"),
				helpers.SecretDataKeyRaw: []byte(`{"data":{"baz":"qux"}}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "invalid-data-contains-raw",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						helpers.SecretDataKeyRaw: "qux",
						"baz":                    "foo",
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, helpers.SecretDataErrorContainsRaw)
			},
		},
		{
			name:     "invalid-empty-raw-data",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: nil,
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "raw portion of vault KV secret was nil")
			},
		},
		{
			name:     "invalid-raw-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"baz": make(chan int),
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name:     "invalid-data-unmarshalable",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"baz": make(chan int),
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseSecretK8sData(t, tt)
		})
	}
}

func assertResponseData(t *testing.T, tt testResponseData) {
	t.Helper()
	resp := tt.respFunc(tt)
	assert.Equalf(t, tt.want, resp.Data(), "Data()")
}

func assertResponseSecret(t *testing.T, tt testResponseSecret) {
	t.Helper()
	resp := tt.respFunc(tt)
	assert.Equalf(t, tt.want, resp.Secret(), "Data()")
}

func assertResponseSecretK8sData(t *testing.T, tt testResponseSecretK8sData) {
	t.Helper()
	resp := tt.respFunc(tt)
	got, err := resp.SecretK8sData(tt.opt)
	if !tt.wantErr(t, err, fmt.Sprintf("SecretK8sData()")) {
		return
	}
	assert.Equalf(t, tt.want, got, "SecretK8sData()")
}
