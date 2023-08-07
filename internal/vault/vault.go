// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api"
)

type PKICertResponse struct {
	CAChain        []string `json:"ca_chain"`
	Certificate    string   `json:"certificate"`
	Expiration     int64    `json:"expiration"`
	IssuingCa      string   `json:"issuing_ca"`
	PrivateKey     string   `json:"private_key"`
	PrivateKeyType string   `json:"private_key_type"`
	SerialNumber   string   `json:"serial_number"`
}

func UnmarshalPKIIssueResponse(resp *api.Secret) (*PKICertResponse, error) {
	b, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	result := &PKICertResponse{}
	if err := json.Unmarshal(b, result); err != nil {
		return nil, err
	}

	return result, nil
}

// MarshalSecretData returns Kubernetes Secret data from an api.Secret
// TODO: move to internal/helpers
func MarshalSecretData(resp *api.Secret) (map[string][]byte, error) {
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	return MarshalData(resp.Data, resp.Data)
}

// MarshalKVData returns Kubernetes Secret data from an api.KVSecret
// TODO: move to internal/helpers
func MarshalKVData(kv *api.KVSecret) (map[string][]byte, error) {
	if kv.Raw == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return MarshalData(kv.Data, kv.Raw.Data)
}

// TODO: move to internal/helpers
func MarshalData(d, raw map[string]interface{}) (map[string][]byte, error) {
	data := make(map[string][]byte)

	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	data["_raw"] = b

	for k, v := range d {
		if k == "_raw" {
			return nil, fmt.Errorf("key '_raw' not permitted in Vault secret")
		}

		switch x := v.(type) {
		case string:
			data[k] = []byte(x)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			data[k] = b
		}
	}

	return data, nil
}
