// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

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

	TransitRequestOptions struct {
		Params  map[string]any
		Headers http.Header
	}

	// TransitOption modifies parameters and/or headers for a Transit request.
	TransitOption func(*TransitRequestOptions)
)

// EncryptWithTransit encrypts data using Vault Transit.
func EncryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte, opts ...TransitOption) ([]byte, error) {
	path := fmt.Sprintf("%s/encrypt/%s", mount, key)

	req := &TransitRequestOptions{
		Params: map[string]any{
			"name":      key,
			"plaintext": base64.StdEncoding.EncodeToString(data),
		},
		Headers: make(http.Header),
	}

	for _, opt := range opts {
		opt(req)
	}

	resp, err := vaultClient.Write(ctx, NewWriteRequest(path, req.Params, req.Headers))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from Vault, path=%s", path)
	}

	return json.Marshal(resp.Data())
}

// DecryptWithTransit decrypts data using Vault Transit.
func DecryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte) ([]byte, error) {
	var v encryptResponse
	err := json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}

	return DecryptCiphertextWithTransit(ctx, vaultClient, mount, key, v.Ciphertext)
}

// DecryptCiphertextWithTransit decrypts a ciphertext value using Vault Transit.
func DecryptCiphertextWithTransit(ctx context.Context, vaultClient Client, mount, key, ciphertext string, opts ...TransitOption) ([]byte, error) {
	path := fmt.Sprintf("%s/decrypt/%s", mount, key)
	req := &TransitRequestOptions{
		Params: map[string]interface{}{
			"name":       key,
			"ciphertext": ciphertext,
		},
		Headers: make(http.Header),
	}

	for _, opt := range opts {
		opt(req)
	}

	resp, err := vaultClient.Write(ctx, NewWriteRequest(path, req.Params, req.Headers))
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

// WithKeyVersion sets the key version for EncryptWithTransit.
// It is ignored when passed to DecryptWithTransit.
func WithKeyVersion(v uint) TransitOption {
	return func(opt *TransitRequestOptions) {
		opt.Params["key_version"] = v
	}
}

func WithNamespace(namespace string) TransitOption {
	return func(opt *TransitRequestOptions) {
		if namespace == "" {
			return
		}
		opt.Headers.Set("X-Vault-Namespace", namespace)
	}
}
