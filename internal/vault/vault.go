// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

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
			decodedValue, err := convertBase64(x)
			if err != nil {
				return nil, err
			}
			data[k] = []byte(decodedValue)
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

func convertBase64(input string) (string, error) {
	base64Pattern := "^[A-Za-z0-9+/]*={0,2}$"
	regex, err := regexp.Compile(base64Pattern)
	isBase64 := regex.MatchString(input)
	if err != nil {
		return "", err
	}
	if isBase64 {
		decodedValue, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", err
		}
		return string(decodedValue), nil
	}
	return input, nil
}
