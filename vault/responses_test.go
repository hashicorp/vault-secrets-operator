// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/helpers"
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

type testResponseWrapInfo struct {
	name     string
	respFunc func(tt testResponseWrapInfo) Response
	secret   *api.Secret
	want     *api.SecretWrapInfo
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
		{
			name:     "auth-fallback-nil-data",
			respFunc: respFunc,
			secret: &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken: "s.abc123",
					Accessor:    "accessor-xyz",
					Policies:    []string{"default", "prometheus"},
					Renewable:   true,
				},
			},
			want: map[string]interface{}{
				"client_token":      "s.abc123",
				"accessor":          "accessor-xyz",
				"policies":          []interface{}{"default", "prometheus"},
				"renewable":         true,
				"lease_duration":    float64(0),
				"token_policies":    interface{}(nil),
				"identity_policies": interface{}(nil),
				"metadata":          interface{}(nil),
				"entity_id":         "",
				"orphan":            false,
				"mfa_requirement":   interface{}(nil),
			},
		},
		{
			name:     "data-takes-precedence-over-auth",
			respFunc: respFunc,
			secret: &api.Secret{
				Data: map[string]interface{}{
					"key": "from-data",
				},
				Auth: &api.SecretAuth{
					ClientToken: "s.abc123",
				},
			},
			want: map[string]interface{}{
				"key": "from-data",
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
		{
			name:     "auth-fallback-token-create",
			respFunc: respFunc,
			secret: &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken: "s.abc123",
					Accessor:    "accessor-xyz",
					Renewable:   true,
				},
			},
			want: map[string][]byte{
				"client_token":      []byte("s.abc123"),
				"accessor":          []byte("accessor-xyz"),
				"renewable":         []byte("true"),
				"orphan":            []byte("false"),
				"lease_duration":    []byte("0"),
				"entity_id":         []byte(""),
				"policies":          []byte(`null`),
				"token_policies":    []byte(`null`),
				"identity_policies": []byte(`null`),
				"metadata":          []byte(`null`),
				"mfa_requirement":   []byte(`null`),
				helpers.SecretDataKeyRaw: []byte(`{"accessor":"accessor-xyz","client_token":"s.abc123","entity_id":"","identity_policies":null,"lease_duration":0,"metadata":null,"mfa_requirement":null,"orphan":false,"policies":null,"renewable":true,"token_policies":null}`),
			},
			wantErr: assert.NoError,
		},
		{
			name:     "auth-fallback-with-template",
			respFunc: respFunc,
			secret: &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken: "s.abc123",
				},
			},
			opt: &helpers.SecretTransformationOption{
				KeyedTemplates: []*helpers.KeyedTemplate{
					{
						Key: "token",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{ get .Secrets "client_token" }}`,
						},
					},
				},
			},
			want: map[string][]byte{
				"client_token":      []byte("s.abc123"),
				"accessor":          []byte(""),
				"renewable":         []byte("false"),
				"orphan":            []byte("false"),
				"lease_duration":    []byte("0"),
				"entity_id":         []byte(""),
				"policies":          []byte(`null`),
				"token_policies":    []byte(`null`),
				"identity_policies": []byte(`null`),
				"metadata":          []byte(`null`),
				"mfa_requirement":   []byte(`null`),
				"token":             []byte("s.abc123"),
				helpers.SecretDataKeyRaw: []byte(`{"accessor":"","client_token":"s.abc123","entity_id":"","identity_policies":null,"lease_duration":0,"metadata":null,"mfa_requirement":null,"orphan":false,"policies":null,"renewable":false,"token_policies":null}`),
			},
			wantErr: assert.NoError,
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

func Test_defaultResponse_WrapInfo(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseWrapInfo) Response {
		return &defaultResponse{
			secret: tt.secret,
		}
	}

	ts := time.Now().UTC()
	tests := []testResponseWrapInfo{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
				WrapInfo: &api.SecretWrapInfo{
					Token:           "1234546",
					Accessor:        "some-accessor",
					TTL:             0,
					CreationTime:    ts,
					CreationPath:    "foo/bar",
					WrappedAccessor: "some-wrapped-accessor",
				},
			},
			respFunc: respFunc,
			want: &api.SecretWrapInfo{
				Token:           "1234546",
				Accessor:        "some-accessor",
				TTL:             0,
				CreationTime:    ts,
				CreationPath:    "foo/bar",
				WrappedAccessor: "some-wrapped-accessor",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertResponseWrapInfo(t, tt)
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
				KeyedTemplates: []*helpers.KeyedTemplate{
					{
						Key: "foo",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- $key := "baz" -}}
{{- printf "ENV_%s=%s" ( $key | upper ) ( get .Secrets $key ) -}}`,
						},
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

func Test_kv1Response_WrapInfo(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseWrapInfo) Response {
		return &kvV1Response{
			secret: tt.secret,
		}
	}

	ts := time.Now().UTC()
	tests := []testResponseWrapInfo{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
				WrapInfo: &api.SecretWrapInfo{
					Token:           "1234546",
					Accessor:        "some-accessor",
					TTL:             0,
					CreationTime:    ts,
					CreationPath:    "foo/bar",
					WrappedAccessor: "some-wrapped-accessor",
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

			assertResponseWrapInfo(t, tt)
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
				KeyedTemplates: []*helpers.KeyedTemplate{
					{
						Key: "foo",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- $key := "baz" -}}
{{- printf "ENV_%s=%s" ( $key | upper ) ( get .Secrets $key ) -}}`,
						},
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

func Test_kv2Response_WrapInfo(t *testing.T) {
	t.Parallel()

	respFunc := func(tt testResponseWrapInfo) Response {
		return &kvV2Response{
			secret: tt.secret,
		}
	}

	ts := time.Now().UTC()
	tests := []testResponseWrapInfo{
		{
			name: "basic",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"bar": "baz",
					},
				},
				WrapInfo: &api.SecretWrapInfo{
					Token:           "1234546",
					Accessor:        "some-accessor",
					TTL:             0,
					CreationTime:    ts,
					CreationPath:    "foo/bar",
					WrappedAccessor: "some-wrapped-accessor",
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

			assertResponseWrapInfo(t, tt)
		})
	}
}

func TestIsLeaseNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *api.ResponseError
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "lease-not-found",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors:     []string{"lease not found"},
			},
			want: true,
		},
		{
			name: "not-lease-not-found",
			err:  &api.ResponseError{StatusCode: http.StatusOK},
			want: false,
		},
		{
			name: "not-lease-not-found-wrong-error",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors:     []string{"another error"},
			},
			want: false,
		},
		{
			name: "not-lease-not-found-multiple-errors",
			err: &api.ResponseError{
				StatusCode: http.StatusBadRequest,
				Errors:     []string{"some error", "another error"},
			},
			want: false,
		},
		{
			name: "not-lease-not-found-wrong-status-code",
			err: &api.ResponseError{
				StatusCode: http.StatusNotFound,
				Errors:     []string{"lease not found"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, IsLeaseNotFoundError(tt.err), "IsLeaseNotFoundError(%v)", tt.err)
		})
	}
}

func TestIsForbiddenError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *api.ResponseError
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "not-forbidden",
			err:  &api.ResponseError{StatusCode: http.StatusOK},
			want: false,
		},
		{
			name: "forbidden",
			err:  &api.ResponseError{StatusCode: http.StatusForbidden},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, IsForbiddenError(tt.err), "IsForbiddenError(%v)", tt.err)
		})
	}
}

func assertResponseData(t *testing.T, tt testResponseData) {
	t.Helper()
	resp := tt.respFunc(tt)
	assert.Equalf(t, tt.want, resp.Data(), "Data()")
}

func assertResponseWrapInfo(t *testing.T, tt testResponseWrapInfo) {
	t.Helper()
	resp := tt.respFunc(tt)
	assert.Equalf(t, tt.want, resp.WrapInfo(), "WrapInfo()")
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
