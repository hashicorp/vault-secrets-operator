package vault

import (
	"encoding/json"

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

func MarshalSecretData(resp *api.Secret) (map[string][]byte, error) {
	data := make(map[string][]byte)

	b, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}
	data["_data"] = b

	for k, v := range resp.Data {
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
