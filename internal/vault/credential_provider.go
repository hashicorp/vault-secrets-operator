// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault/credentialproviders"
)

const (
	providerMethodKubernetes string = "kubernetes"
	providerMethodJWT        string = "jwt"
)

var (
	providerMethodsSupported = []string{providerMethodKubernetes, providerMethodJWT}

	_ CredentialProvider = (*credentialproviders.KubernetesCredentialProvider)(nil)
	_ CredentialProvider = (*credentialproviders.JWTCredentialProvider)(nil)
)

type CredentialProvider interface {
	Init(ctx context.Context, client ctrlclient.Client, object *secretsv1alpha1.VaultAuth, providerNamespace string) error
	GetUID() types.UID
	GetNamespace() string
	GetCreds(context.Context, ctrlclient.Client) (map[string]interface{}, error)
}

func NewCredentialProvider(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) (CredentialProvider, error) {
	if authObj == nil {
		return nil, fmt.Errorf("non-nil VaultAuth pointer is required to create a credential provider")
	}

	switch authObj.Spec.Method {
	case providerMethodJWT:
		provider := &credentialproviders.JWTCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	case providerMethodKubernetes:
		provider := &credentialproviders.KubernetesCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
	}
}
