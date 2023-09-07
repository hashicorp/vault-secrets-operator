// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
