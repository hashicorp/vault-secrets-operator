// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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

// TODO: move to internal/helpers
func MakeSecretK8sData(d, raw map[string]interface{}) (map[string][]byte, error) {
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
