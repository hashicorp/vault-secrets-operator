// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/hcp"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"
)

type CredentialProviderFactoryFunc func(context.Context, client.Client, client.Object, string) (provider.CredentialProviderBase, error)

var ProviderMethodsSupported = []string{
	consts.ProviderMethodKubernetes,
	consts.ProviderMethodJWT,
	consts.ProviderMethodAppRole,
	consts.ProviderMethodAWS,
	consts.ProviderMethodGCP,
	hcp.ProviderMethodServicePrincipal,
}

// NewCredentialProvider returns a new provider.CredentialProviderBase instance
// for the given object. It supports objects of type VaultAuth and HCPAuth.
func NewCredentialProvider(ctx context.Context, client client.Client, obj client.Object, providerNamespace string) (provider.CredentialProviderBase, error) {
	var p provider.CredentialProviderBase
	switch authObj := obj.(type) {
	case *v1beta1.VaultAuth:
		var prov vault.CredentialProvider
		switch authObj.Spec.Method {
		case consts.ProviderMethodJWT:
			prov = &vault.JWTCredentialProvider{}
		case consts.ProviderMethodAppRole:
			prov = &vault.AppRoleCredentialProvider{}
		case consts.ProviderMethodKubernetes:
			prov = &vault.KubernetesCredentialProvider{}
		case consts.ProviderMethodAWS:
			prov = &vault.AWSCredentialProvider{}
		case consts.ProviderMethodGCP:
			prov = &vault.GCPCredentialProvider{}
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

// CredentialProviderFactory provides an interface for setting up new
// provider.CredentialProvider instances.
type CredentialProviderFactory interface {
	New(ctx context.Context, c client.Client, obj client.Object, providerNamespace string) (provider.CredentialProviderBase, error)
}

type defaultCredentialProviderFactory struct {
	factoryFunc CredentialProviderFactoryFunc
}

// New returns a new provider.CredentialProviderBase instance for the given
// object. It supports objects of type VaultAuth and HCPAuth.
func (f *defaultCredentialProviderFactory) New(ctx context.Context, c client.Client, obj client.Object, providerNamespace string) (provider.CredentialProviderBase, error) {
	return f.factoryFunc(ctx, c, obj, providerNamespace)
}

// NewCredentialProviderFactory returns a new CredentialProviderFactory.
func NewCredentialProviderFactory() CredentialProviderFactory {
	return &defaultCredentialProviderFactory{
		factoryFunc: NewCredentialProvider,
	}
}
