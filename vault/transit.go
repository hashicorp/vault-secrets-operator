// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/base64"
	"fmt"

	"k8s.io/apimachinery/pkg/util/json"
)

type (
	// only here to make encrypting/decrypting a bit simpler, by leveraging json.Marshal
	encryptResponse struct {
		Context    string `json:"context"`
		Ciphertext string `json:"ciphertext"`
	}
	// only here to make encrypting/decrypting a bit simpler, by leveraging json.Marshal
	decryptResponse struct {
		Plaintext string `json:"plaintext"`
	}

	TransitOption func(m map[string]any)
)

// EncryptWithTransit encrypts data using Vault Transit.
func EncryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte, opts ...TransitOption) ([]byte, error) {
	path := fmt.Sprintf("%s/encrypt/%s", mount, key)

	params := map[string]any{
		"name":      key,
		"plaintext": base64.StdEncoding.EncodeToString(data),
	}

	for _, opt := range opts {
		opt(params)
	}

	resp, err := vaultClient.Write(ctx, NewWriteRequest(path, params, nil))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from Vault, path=%s", path)
	}

	return json.Marshal(resp.Data())
}

// DecryptWithTransit decrypts data using Vault Transit.
func DecryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte, opts ...TransitOption) ([]byte, error) {
	var v encryptResponse
	err := json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("%s/decrypt/%s", mount, key)
	params := map[string]interface{}{
		"name":       key,
		"ciphertext": v.Ciphertext,
	}

	resp, err := vaultClient.Write(ctx, NewWriteRequest(path, params, nil))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from Vault, path=%s", path)
	}

	b, err := json.Marshal(resp.Data())
	if err != nil {
		return nil, err
	}

	var d decryptResponse
	err = json.Unmarshal(b, &d)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(d.Plaintext)
}

func WithKeyVersion(v int) TransitOption {
	return func(m map[string]any) { m["key_version"] = v }
}
