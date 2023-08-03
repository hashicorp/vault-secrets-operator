// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/hcp"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/vault"
)

var ProviderMethodsSupported = []string{
	vault.ProviderMethodKubernetes,
	vault.ProviderMethodJWT,
	vault.ProviderMethodAppRole,
	vault.ProviderMethodAWS,
	hcp.ProviderMethodServicePrincipal,
}

func NewCredentialProvider(ctx context.Context, client client.Client, obj client.Object, providerNamespace string) (provider.CredentialProviderBase, error) {
	var p provider.CredentialProviderBase
	switch authObj := obj.(type) {
	case *v1beta1.VaultAuth:
		var prov vault.CredentialProvider
		switch authObj.Spec.Method {
		case vault.ProviderMethodJWT:
			prov = &vault.JWTCredentialProvider{}
		case vault.ProviderMethodAppRole:
			prov = &vault.AppRoleCredentialProvider{}
		case vault.ProviderMethodKubernetes:
			prov = &vault.KubernetesCredentialProvider{}
		case vault.ProviderMethodAWS:
			prov = &vault.AWSCredentialProvider{}
		default:
			return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
		}

		if err := prov.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}

		p = prov
	case *v1beta1.HCPAuth:
		var prov hcp.CredentialProviderHCP
		switch authObj.Spec.Method {
		case hcp.ProviderMethodServicePrincipal:
			prov = &hcp.ServicePrincipleCredentialProvider{}
		default:
			return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
		}

		if err := prov.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}

		p = prov
	default:
		return nil, fmt.Errorf("unsupported auth object %T", authObj)
	}
	return p, nil
}
