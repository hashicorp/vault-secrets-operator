// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestMakeSecretK8sData(t *testing.T) {
	// tests use this to ensure proper ordering of the value for `_raw`
	marshalRaw := func(t *testing.T, d any) []byte {
		b, err := json.Marshal(d)
		require.NoError(t, err)
		return b
	}
	tests := []struct {
		name    string
		data    map[string]interface{}
		raw     map[string]interface{}
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "equal-raw-data",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				"baz": []byte(`qux`),
				"foo": []byte(`biff`),
				"_raw": marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "mixed",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"foo":  "bar",
				"biff": "buz",
				"buz":  1,
			},
			want: map[string][]byte{
				"baz": []byte(`qux`),
				"foo": []byte(`biff`),
				"_raw": marshalRaw(t, map[string]any{
					"biff": "buz",
					"foo":  "bar",
					"buz":  1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name:    "nil-data-nil-raw",
			data:    nil,
			raw:     nil,
			want:    map[string][]byte{"_raw": []byte(`null`)},
			wantErr: assert.NoError,
		},
		{
			name: "nil-data",
			data: nil,
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				"_raw": marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "nil-raw",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: nil,
			want: map[string][]byte{
				"_raw": []byte(`null`),
				"baz":  []byte("qux"),
				"foo":  []byte("biff"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-raw-data-unmarshalable",
			data: nil,
			raw: map[string]interface{}{
				"baz": make(chan int),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name: "invalid-data-unmarshalable",
			data: map[string]interface{}{
				"baz": make(chan int),
			},
			raw:  nil,
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name: "invalid-data-contains-raw",
			data: map[string]interface{}{
				"_raw": "qux",
				"baz":  "foo",
			},
			raw: map[string]interface{}{
				"baz": "foo",
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "key '_raw' not permitted in Vault secret")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeSecretK8sData(tt.data, tt.raw)
			if !tt.wantErr(t, err, fmt.Sprintf("MakeSecretK8sData(%v, %v)", tt.data, tt.raw)) {
				return
			}
			assert.Equalf(t, tt.want, got, "MakeSecretK8sData(%v, %v)", tt.data, tt.raw)
		})
	}
}

func Test_MarshalSecretData(t *testing.T) {
	tests := map[string]struct {
		input    api.Secret
		expected map[string]string
	}{
		"secrets included base64": {
			input: api.Secret{
				Data: map[string]interface{}{
					"key_algorithm":    "KEY_ALG_RSA_2048",
					"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
					"private_key_data": "eyJ0eXBlIjoic2VydmljZV9hY2NvdW50IiwicHJvamVjdF9pZCI6IlBST0pFQ1RfSUQiLCJwcml2YXRlX2tleV9pZCI6IktFWV9JRCIsInByaXZhdGVfa2V5IjoiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5QUklWQVRFX0tFWVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwiY2xpZW50X2VtYWlsIjoiU0VSVklDRV9BQ0NPVU5UX0VNQUlMIiwiY2xpZW50X2lkIjoiQ0xJRU5UX0lEIiwiYXV0aF91cmkiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsInRva2VuX3VyaSI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsImNsaWVudF94NTA5X2NlcnRfdXJsIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9TRVJWSUNFX0FDQ09VTlRfRU1BSUwifQ==",
				},
			},
			expected: map[string]string{
				"_raw":             "{\"key_algorithm\":\"KEY_ALG_RSA_2048\",\"key_type\":\"TYPE_GOOGLE_CREDENTIALS_FILE\",\"private_key_data\":\"eyJ0eXBlIjoic2VydmljZV9hY2NvdW50IiwicHJvamVjdF9pZCI6IlBST0pFQ1RfSUQiLCJwcml2YXRlX2tleV9pZCI6IktFWV9JRCIsInByaXZhdGVfa2V5IjoiLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tXG5QUklWQVRFX0tFWVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwiY2xpZW50X2VtYWlsIjoiU0VSVklDRV9BQ0NPVU5UX0VNQUlMIiwiY2xpZW50X2lkIjoiQ0xJRU5UX0lEIiwiYXV0aF91cmkiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20vby9vYXV0aDIvYXV0aCIsInRva2VuX3VyaSI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tlbiIsImF1dGhfcHJvdmlkZXJfeDUwOV9jZXJ0X3VybCI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL29hdXRoMi92MS9jZXJ0cyIsImNsaWVudF94NTA5X2NlcnRfdXJsIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9TRVJWSUNFX0FDQ09VTlRfRU1BSUwifQ==\"}",
				"key_algorithm":    "KEY_ALG_RSA_2048",
				"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
				"private_key_data": `{"type":"service_account","project_id":"PROJECT_ID","private_key_id":"KEY_ID","private_key":"-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n-----END PRIVATE KEY-----\n","client_email":"SERVICE_ACCOUNT_EMAIL","client_id":"CLIENT_ID","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/SERVICE_ACCOUNT_EMAIL"}`,
			},
		},
		"secrets include regular string": {
			input: api.Secret{
				Data: map[string]interface{}{
					"key_algorithm":    "KEY_ALG_RSA_2048",
					"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
					"private_key_data": "test string",
				},
			},
			expected: map[string]string{
				"_raw":             "{\"key_algorithm\":\"KEY_ALG_RSA_2048\",\"key_type\":\"TYPE_GOOGLE_CREDENTIALS_FILE\",\"private_key_data\":\"test string\"}",
				"key_algorithm":    "KEY_ALG_RSA_2048",
				"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
				"private_key_data": "test string",
			},
		},
		"secrets include a valid base64": {
			input: api.Secret{
				Data: map[string]interface{}{
					"key_algorithm":    "KEY_ALG_RSA_2048",
					"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
					"private_key_data": "SGVsbG8gV29ybGQh!!",
				},
			},
			expected: map[string]string{
				"_raw":             "{\"key_algorithm\":\"KEY_ALG_RSA_2048\",\"key_type\":\"TYPE_GOOGLE_CREDENTIALS_FILE\",\"private_key_data\":\"SGVsbG8gV29ybGQh!!\"}",
				"key_algorithm":    "KEY_ALG_RSA_2048",
				"key_type":         "TYPE_GOOGLE_CREDENTIALS_FILE",
				"private_key_data": "SGVsbG8gV29ybGQh!!",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := MarshalSecretData(&tc.input)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected["private_key_data"], string(result["private_key_data"]))
			assert.Equal(t, tc.expected["key_algorithm"], string(result["key_algorithm"]))
			assert.Equal(t, tc.expected["key_type"], string(result["key_type"]))
			assert.Equal(t, tc.expected["_raw"], string(result["_raw"]))
		})
	}
}
