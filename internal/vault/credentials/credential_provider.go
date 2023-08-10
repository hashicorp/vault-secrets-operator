// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

const (
	ProviderMethodKubernetes string = "kubernetes"
	ProviderMethodJWT        string = "jwt"
	ProviderMethodAppRole    string = "appRole"
	ProviderMethodAWS        string = "aws"
)

var ProviderMethodsSupported = []string{
	ProviderMethodKubernetes,
	ProviderMethodJWT,
	ProviderMethodAppRole,
	ProviderMethodAWS,
}

type CredentialProvider interface {
	Init(ctx context.Context, client ctrlclient.Client, object *secretsv1beta1.VaultAuth, providerNamespace string) error
	GetUID() types.UID
	GetNamespace() string
	GetCreds(context.Context, ctrlclient.Client) (map[string]interface{}, error)
}

func NewCredentialProvider(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) (CredentialProvider, error) {
	if authObj == nil {
		return nil, fmt.Errorf("non-nil VaultAuth pointer is required to create a credential provider")
	}

	switch authObj.Spec.Method {
	case ProviderMethodJWT:
		provider := &JWTCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	case ProviderMethodAppRole:
		provider := &AppRoleCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	case ProviderMethodKubernetes:
		provider := &KubernetesCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	case ProviderMethodAWS:
		provider := &AWSCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
	}
}
