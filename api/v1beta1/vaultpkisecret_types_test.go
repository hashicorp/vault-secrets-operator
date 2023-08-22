// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultPKISecret_GetIssuerAPIData(t *testing.T) {
	tests := []struct {
		name string
		spec VaultPKISecretSpec
		want map[string]interface{}
	}{
		{
			name: "all-fields",
			spec: VaultPKISecretSpec{
				CommonName:       "qux",
				AltNames:         []string{"foo", "baz"},
				IPSans:           []string{"buz", "qux"},
				URISans:          []string{"*.foo.net", "*.baz.net"},
				OtherSans:        []string{"other1", "other2"},
				TTL:              "30s",
				NotAfter:         "2026-05-01T00:00:00Z",
				Format:           "pem",
				PrivateKeyFormat: "rsa",
			},
			want: map[string]interface{}{
				"common_name":             "qux",
				"alt_names":               "foo,baz",
				"ip_sans":                 "buz,qux",
				"uri_sans":                "*.foo.net,*.baz.net",
				"other_sans":              "other1,other2",
				"ttl":                     "30s",
				"not_after":               "2026-05-01T00:00:00Z",
				"exclude_cn_from_sans":    false,
				"format":                  "pem",
				"private_key_format":      "rsa",
				"remove_roots_from_chain": true,
			},
		},
		{
			name: "without-format",
			spec: VaultPKISecretSpec{
				CommonName:       "qux",
				AltNames:         []string{"foo", "baz"},
				IPSans:           []string{"buz", "qux"},
				URISans:          []string{"*.foo.net", "*.baz.net"},
				OtherSans:        []string{"other1", "other2"},
				TTL:              "30s",
				NotAfter:         "2026-05-01T00:00:00Z",
				PrivateKeyFormat: "rsa",
			},
			want: map[string]interface{}{
				"common_name":             "qux",
				"alt_names":               "foo,baz",
				"ip_sans":                 "buz,qux",
				"uri_sans":                "*.foo.net,*.baz.net",
				"other_sans":              "other1,other2",
				"ttl":                     "30s",
				"not_after":               "2026-05-01T00:00:00Z",
				"exclude_cn_from_sans":    false,
				"private_key_format":      "rsa",
				"remove_roots_from_chain": true,
			},
		},
		{
			name: "without-private-key-format",
			spec: VaultPKISecretSpec{
				CommonName: "qux",
				AltNames:   []string{"foo", "baz"},
				IPSans:     []string{"buz", "qux"},
				URISans:    []string{"*.foo.net", "*.baz.net"},
				OtherSans:  []string{"other1", "other2"},
				TTL:        "30s",
				NotAfter:   "2026-05-01T00:00:00Z",
				Format:     "pem",
			},
			want: map[string]interface{}{
				"common_name":             "qux",
				"alt_names":               "foo,baz",
				"ip_sans":                 "buz,qux",
				"uri_sans":                "*.foo.net,*.baz.net",
				"other_sans":              "other1,other2",
				"ttl":                     "30s",
				"not_after":               "2026-05-01T00:00:00Z",
				"exclude_cn_from_sans":    false,
				"format":                  "pem",
				"remove_roots_from_chain": true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VaultPKISecret{
				Spec: tt.spec,
			}
			got := v.GetIssuerAPIData()
			assert.Equal(t, tt.want, got, "GetIssuerAPIData() = %v, want %v", got, tt.want)
		})
	}
}
