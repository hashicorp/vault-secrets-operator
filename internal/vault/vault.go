// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
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

// MakeVaultClient creates a Vault API client from the config in the
// VaultConnection.Spec
func MakeVaultClient(ctx context.Context, vaultConnection *secretsv1alpha1.VaultConnection, k8sClient client.Client) (*api.Client, error) {
	l := log.FromContext(ctx)

	vaultCAbytes := []byte{}
	if vaultConnection.Spec.CACertSecretRef != "" {
		vaultCASecret := &corev1.Secret{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Namespace: vaultConnection.ObjectMeta.Namespace,
			Name:      vaultConnection.Spec.CACertSecretRef,
		}, vaultCASecret); err != nil {
			return nil, err
		}
		vaultCAbytes = vaultCASecret.Data["ca.crt"]
	}

	config := api.DefaultConfig()

	config.Address = vaultConnection.Spec.Address
	config.ConfigureTLS(&api.TLSConfig{
		Insecure:      vaultConnection.Spec.SkipTLSVerify,
		TLSServerName: vaultConnection.Spec.TLSServerName,
		CACertBytes:   vaultCAbytes,
	})

	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	return c, nil
}
