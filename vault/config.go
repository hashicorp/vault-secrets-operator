// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	vconsts "github.com/hashicorp/vault/sdk/helper/consts"
	v1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/consts"
)

// ClientConfig contains the connection and auth information to construct a
// Vault Client.
type ClientConfig struct {
	// CACertSecretRef is the name of a k8 secret that contains a data key
	// "ca.crt" that holds a CA cert that can be used to validate the
	// certificate presented by the Vault server
	CACertSecretRef string
	// CACertPath is the path to a CA certificate file on the filesystem that
	// can be used to validate the certificate presented by the Vault server.
	// Mutually exclusive with CACertSecretRef.
	CACertPath string
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
	// Headers are http headers to set on the Vault client
	Headers http.Header
	// Timeout applied to all Vault requests. If not set, the default timeout from
	// the Vault API client config is used.
	Timeout *time.Duration
}

// MakeVaultClient creates a Vault api.Client from a ClientConfig.
func MakeVaultClient(ctx context.Context, cfg *ClientConfig, client ctrlclient.Client) (*api.Client, error) {
	l := log.FromContext(ctx)
	if cfg == nil {
		return nil, fmt.Errorf("ClientConfig was nil")
	}

	if err := validateCACertConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid CA cert config: %w", err)
	}

	var b []byte
	if cfg.CACertSecretRef != "" {
		// Load CA certificate from k8s Secret
		if client == nil {
			return nil, fmt.Errorf("ctrl-runtime Client was nil and CCACertSecretRef was provided")
		}

		objKey := ctrlclient.ObjectKey{
			Namespace: cfg.K8sNamespace,
			Name:      cfg.CACertSecretRef,
		}
		s := &v1.Secret{}
		if err := client.Get(ctx, objKey, s); err != nil {
			return nil, err
		}

		var ok bool
		key := consts.TLSSecretCAKey
		if b, ok = s.Data[key]; !ok {
			return nil, fmt.Errorf(`%q not present in the CA secret %q`, key, objKey)
		}

		if !cfg.SkipTLSVerify {
			err := validateCACertChain(b)
			if err != nil {
				return nil, fmt.Errorf("invalid CA cert in secret %q: %w", objKey, err)
			}
		}
	} else if cfg.CACertPath != "" {
		// Load CA certificate from filesystem
		var err error
		b, err = os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %q: %w", cfg.CACertPath, err)
		}

		if !cfg.SkipTLSVerify {
			err := validateCACertChain(b)
			if err != nil {
				return nil, fmt.Errorf("no valid certificates found in CA cert file %q", cfg.CACertPath)
			}
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

	if cfg.Timeout != nil {
		config.Timeout = *cfg.Timeout
	}

	config.CloneToken = true
	config.CloneHeaders = true
	config.CloneTLSConfig = true

	c, err := api.NewClient(config)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}
	if _, exists := cfg.Headers[vconsts.NamespaceHeaderName]; exists {
		return nil, fmt.Errorf("setting header %q on VaultConnection is not permitted", vconsts.NamespaceHeaderName)
	}
	for k, values := range cfg.Headers {
		for _, v := range values {
			c.AddHeader(k, v)
		}
	}
	if cfg.VaultNamespace != "" {
		c.SetNamespace(cfg.VaultNamespace)
	}

	return c, nil
}

// validateCACertConfig ensures CACertSecretRef and CACertPath are mutually exclusive,
// and that CACertPath does not contain path traversal sequences.
func validateCACertConfig(cfg *ClientConfig) error {
	if cfg.CACertPath != "" {
		if cfg.CACertSecretRef != "" {
			return fmt.Errorf("CACertPath and CACertSecretRef are mutually exclusive, only one can be set")
		}

		if strings.Contains(cfg.CACertPath, "..") {
			return fmt.Errorf("path contains traversal sequence: %q", cfg.CACertPath)
		}
	}
	return nil
}

// validateCACertChain checks that the provided CA cert PEM contains at least one valid certificate.
// We only need to perform this validation when SkipTLSVerify is false.
func validateCACertChain(caCertPEM []byte) error {
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		return fmt.Errorf("no valid certificates found in CA cert data")
	}
	return nil
}
