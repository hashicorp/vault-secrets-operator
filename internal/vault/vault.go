// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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

// VaultClientConfig contains the connection and auth information to construct a
// Vault client
type VaultClientConfig struct {
	// CACertSecretRef is the name of a k8 secret that contains a data key
	// "ca.crt" that holds a CA cert that can be used to validate the
	// certificate presented by the Vault server
	CACertSecretRef string
	// K8sNamespace the namespace of the CACertSecretRef secret
	K8sNamespace string
	// Address is the URL of the Vault server
	Address string
	// SkipTLSVerify controls whether the Vault server's TLS certificate is
	// verified
	SkipTLSVerify bool
	// TLSServerName is the name to use as the SNI host when connecting via TLS
	// to Vault
	TLSServerName string
	// VaultNamespace is the namespace in Vault to auth to
	VaultNamespace string
	// AuthLogin for Vault getting a vault token
	AuthLogin AuthLogin
}

func (c *VaultClientConfig) SetAuthLogin(a AuthLogin) {
	c.AuthLogin = a
}

// MakeVaultClient creates a Vault API client from a VaultClientConfig
func MakeVaultClient(ctx context.Context, vaultConfig *VaultClientConfig, client client.Client) (*api.Client, error) {
	l := log.FromContext(ctx)
	if vaultConfig == nil {
		return nil, fmt.Errorf("VaultClientConfig was nil")
	}

	vaultCAbytes := []byte{}
	if vaultConfig.CACertSecretRef != "" {
		vaultCASecret := &corev1.Secret{}
		if err := client.Get(ctx, types.NamespacedName{
			Namespace: vaultConfig.K8sNamespace,
			Name:      vaultConfig.CACertSecretRef,
		}, vaultCASecret); err != nil {
			return nil, err
		}
		var ok bool
		if vaultCAbytes, ok = vaultCASecret.Data["ca.crt"]; !ok {
			return nil, fmt.Errorf(`"ca.crt" was empty in the CA secret %s/%s`, vaultConfig.K8sNamespace, vaultConfig.CACertSecretRef)
		}
	}

	config := api.DefaultConfig()

	config.Address = vaultConfig.Address
	config.ConfigureTLS(&api.TLSConfig{
		Insecure:      vaultConfig.SkipTLSVerify,
		TLSServerName: vaultConfig.TLSServerName,
		CACertBytes:   vaultCAbytes,
	})

	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	if vaultConfig.VaultNamespace != "" {
		c.SetNamespace(vaultConfig.VaultNamespace)
	}

	return c, nil
}
