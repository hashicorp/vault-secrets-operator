// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ClientConfig contains the connection and auth information to construct a
// Vault Client.
type ClientConfig struct {
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
}

// MakeVaultClient creates a Vault api.Client from a ClientConfig.
func MakeVaultClient(ctx context.Context, cfg *ClientConfig, client ctrlclient.Client) (*api.Client, error) {
	l := log.FromContext(ctx)
	if cfg == nil {
		return nil, fmt.Errorf("ClientConfig was nil")
	}

	var b []byte
	if cfg.CACertSecretRef != "" {
		s := &v1.Secret{}
		if err := client.Get(ctx, types.NamespacedName{
			Namespace: cfg.K8sNamespace,
			Name:      cfg.CACertSecretRef,
		}, s); err != nil {
			return nil, err
		}
		var ok bool
		if b, ok = s.Data["ca.crt"]; !ok {
			return nil, fmt.Errorf(`"ca.crt" was empty in the CA secret %s/%s`, cfg.K8sNamespace, cfg.CACertSecretRef)
		}
	}

	config := api.DefaultConfig()

	config.Address = cfg.Address
	if err := config.ConfigureTLS(&api.TLSConfig{
		Insecure:      cfg.SkipTLSVerify,
		TLSServerName: cfg.TLSServerName,
		CACertBytes:   b,
	}); err != nil {
		return nil, err
	}

	config.CloneToken = true
	config.CloneHeaders = true

	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	if cfg.VaultNamespace != "" {
		c.SetNamespace(cfg.VaultNamespace)
	}

	return c, nil
}
