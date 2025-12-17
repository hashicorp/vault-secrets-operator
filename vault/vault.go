// Copyright IBM Corp. 2022, 2025
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
	if resp == nil {
		return nil, fmt.Errorf("vault secret response is nil")
	}

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
