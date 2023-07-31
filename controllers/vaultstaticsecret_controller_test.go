// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"fmt"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func Test_makeK8sSecret(t *testing.T) {
	tests := map[string]struct {
		vaultSecret       *api.KVSecret
		expectedK8sSecret map[string][]byte
		expectedError     error
	}{
		"normal": {
			vaultSecret: &api.KVSecret{
				Data: map[string]interface{}{
					"password": "applejuice",
				},
				Raw: &api.Secret{
					Data: map[string]interface{}{
						"password": "applejuice",
					},
				},
			},
			expectedK8sSecret: map[string][]byte{
				"password": []byte("applejuice"),
				"_raw":     []byte(`{"password":"applejuice"}`),
			},
			expectedError: nil,
		},
		"empty raw": {
			vaultSecret: &api.KVSecret{
				Data: map[string]interface{}{},
			},
			expectedK8sSecret: nil,
			expectedError:     fmt.Errorf("raw portion of vault KV secret was nil"),
		},
		"empty data": {
			vaultSecret: &api.KVSecret{
				Raw: &api.Secret{
					Data: map[string]interface{}{
						"password": "applejuice",
					},
				},
			},
			expectedK8sSecret: map[string][]byte{
				"_raw": []byte(`{"password":"applejuice"}`),
			},
			expectedError: nil,
		},
		"empty everything": {
			vaultSecret: &api.KVSecret{
				Raw:  &api.Secret{},
				Data: map[string]interface{}{},
			},
			expectedK8sSecret: map[string][]byte{
				"_raw": []byte("null"),
			},
			expectedError: nil,
		},
		"_raw in secret": {
			vaultSecret: &api.KVSecret{
				Data: map[string]interface{}{
					"password": "applejuice",
					"_raw":     "not allowed",
				},
				Raw: &api.Secret{
					Data: map[string]interface{}{
						"password": "applejuice",
					},
				},
			},
			expectedK8sSecret: nil,
			expectedError:     fmt.Errorf("key '_raw' not permitted in Vault secret"),
		},
		"fail to marshal secret data": {
			vaultSecret: &api.KVSecret{
				Data: map[string]interface{}{
					"password": make(chan int),
				},
				Raw: &api.Secret{
					Data: map[string]interface{}{
						"password": true,
					},
				},
			},
			expectedK8sSecret: nil,
			expectedError:     fmt.Errorf(`json: unsupported type: chan int`),
		},
		"fail to marshal secret raw": {
			vaultSecret: &api.KVSecret{
				Raw: &api.Secret{
					Data: map[string]interface{}{
						"password": make(chan int),
					},
				},
			},
			expectedK8sSecret: nil,
			expectedError:     fmt.Errorf("json: unsupported type: chan int"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			k8sSecret, err := makeK8sSecret(tc.vaultSecret)
			if tc.expectedError != nil {
				assert.EqualError(t, err, tc.expectedError.Error())
				assert.Nil(t, k8sSecret)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedK8sSecret, k8sSecret)
			}
		})
	}
}
