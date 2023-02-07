// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/base64"
	"fmt"

	"k8s.io/apimachinery/pkg/util/json"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	v1alpha12 "github.com/hashicorp/vault-secrets-operator/internal/common"
)

type transitEncDecFunc func(context.Context, Client, string, string, []byte) ([]byte, error)

func EncryptWithTransitFromObjKey(ctx context.Context, ctrlClient ctrlclient.Client, key ctrlclient.ObjectKey, data []byte) ([]byte, error) {
	return doWithTransitFromObjKey(ctx, ctrlClient, key, data, EncryptWithTransit)
}

func DecryptWithTransitFromObjKey(ctx context.Context, ctrlClient ctrlclient.Client, key ctrlclient.ObjectKey, data []byte) ([]byte, error) {
	return doWithTransitFromObjKey(ctx, ctrlClient, key, data, DecryptWithTransit)
}

func EncryptWithTransitFromObj(ctx context.Context, ctrlClient ctrlclient.Client, transitObj *v1alpha1.VaultTransit, data []byte) ([]byte, error) {
	return doWithTransitFromObj(ctx, ctrlClient, transitObj, data, EncryptWithTransit)
}

func DecryptWithTransitFromObj(ctx context.Context, ctrlClient ctrlclient.Client, transitObj *v1alpha1.VaultTransit, data []byte) ([]byte, error) {
	return doWithTransitFromObj(ctx, ctrlClient, transitObj, data, DecryptWithTransit)
}

func doWithTransitFromObjKey(ctx context.Context, ctrlClient ctrlclient.Client, key ctrlclient.ObjectKey, data []byte, f transitEncDecFunc) ([]byte, error) {
	transitObj, err := v1alpha12.GetVaultTransit(ctx, ctrlClient, key)
	if err != nil {
		return nil, err
	}

	return doWithTransitFromObj(ctx, ctrlClient, transitObj, data, f)
}

func doWithTransitFromObj(ctx context.Context, client ctrlclient.Client, transitObj *v1alpha1.VaultTransit, data []byte, f transitEncDecFunc) ([]byte, error) {
	c, err := NewClient(ctx, client, transitObj)
	if err != nil {
		return nil, err
	}

	if err := c.Login(ctx, client); err != nil {
		return nil, err
	}

	return f(ctx, c, transitObj.Spec.Mount, transitObj.Spec.Key, data)
}

type (
	EncryptResponse struct {
		Context    string `json:"context"`
		Ciphertext string `json:"ciphertext"`
	}
	DecryptResponse struct {
		Plaintext string `json:"plaintext"`
	}
)

func EncryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte) ([]byte, error) {
	path := fmt.Sprintf("%s/encrypt/%s", mount, key)
	resp, err := vaultClient.Write(ctx, path,
		map[string]interface{}{
			"name":      key,
			"plaintext": base64.StdEncoding.EncodeToString(data),
		},
	)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from Vault, path=%s", path)
	}

	return json.Marshal(resp.Data)
}

func DecryptWithTransit(ctx context.Context, vaultClient Client, mount, key string, data []byte) ([]byte, error) {
	var v EncryptResponse
	err := json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("%s/decrypt/%s", mount, key)
	params := map[string]interface{}{
		"name":       key,
		"ciphertext": v.Ciphertext,
	}

	resp, err := vaultClient.Write(ctx, path, params)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from Vault, path=%s", path)
	}

	b, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	var d DecryptResponse
	err = json.Unmarshal(b, &d)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(d.Plaintext)
}
