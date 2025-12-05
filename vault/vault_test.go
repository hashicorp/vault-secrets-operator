// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalPKIIssueResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    *api.Secret
		want    *PKICertResponse
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "empty-data",
			resp: &api.Secret{
				Data: map[string]any{},
			},
			want:    &PKICertResponse{},
			wantErr: assert.NoError,
		},
		{
			name: "populated",
			resp: &api.Secret{
				Data: map[string]any{
					"ca_chain":         []string{"ca1", "ca2"},
					"certificate":      "cert1",
					"expiration":       1709566637,
					"issuing_ca":       "root",
					"private_key":      "key1",
					"private_key_type": "rsa",
					"serial_number":    "1",
				},
			},
			want: &PKICertResponse{
				CAChain:        []string{"ca1", "ca2"},
				Certificate:    "cert1",
				Expiration:     1709566637,
				IssuingCa:      "root",
				PrivateKey:     "key1",
				PrivateKeyType: "rsa",
				SerialNumber:   "1",
			},
			wantErr: assert.NoError,
		},
		{
			name:    "nil-vault-secret-data",
			resp:    &api.Secret{},
			want:    &PKICertResponse{},
			wantErr: assert.NoError,
		},
		{
			name: "nil-vault-secret",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "vault secret response is nil")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPKIIssueResponse(tt.resp)
			if !tt.wantErr(t, err, fmt.Sprintf("UnmarshalPKIIssueResponse(%v)", tt.resp)) {
				return
			}
			assert.Equalf(t, tt.want, got, "UnmarshalPKIIssueResponse(%v)", tt.resp)
		})
	}
}
