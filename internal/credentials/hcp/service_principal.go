// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hcp

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/errors"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

const (
	ProviderMethodServicePrincipal = "servicePrincipal"
	ProviderSecretClientID         = "clientID"
	ProviderSecretClientSecret     = "clientSecret"
)

var _ CredentialProviderHCP = (*ServicePrincipleCredentialProvider)(nil)

// ServicePrincipleCredentialProvider provides credentials for authenticating to
// HCP using a service principal. For security reasons, only project-level
// service principals should ever be used.
type ServicePrincipleCredentialProvider struct {
	authObj           *secretsv1beta1.HCPAuth
	providerNamespace string
	uid               types.UID
}

// GetNamespace returns the K8s Namespace of the credential source.
func (l *ServicePrincipleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

// GetUID returns the K8s UID of the credential source.
func (l *ServicePrincipleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *ServicePrincipleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client,
	authObj *secretsv1beta1.HCPAuth, providerNamespace string,
) error {
	logger := log.FromContext(ctx)
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	// We use the UID of the secret which holds the HCP service principle's
	// credentials.
	objKey := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.ServicePrincipal.SecretRef,
	}
	secret, err := helpers.GetSecret(ctx, client, objKey)
	if err != nil {
		logger.Error(err,
			"Init() failed to get secret", "secretObjKey", objKey)
		return err
	}
	l.uid = secret.UID
	return nil
}

// GetCreds returns the credentials as from their source.
func (l *ServicePrincipleCredentialProvider) GetCreds(ctx context.Context,
	client ctrlclient.Client,
) (map[string]any, error) {
	objKey := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.ServicePrincipal.SecretRef,
	}

	secret, err := helpers.GetSecret(ctx, client, objKey)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", errors.InvalidCredentialDataError, err)
	}

	keys := []string{ProviderSecretClientSecret, ProviderSecretClientID}
	result := make(map[string]any, len(keys))
	var invalidKeys []string
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok || len(v) == 0 {
			invalidKeys = append(invalidKeys, k)
			continue
		}
		result[k] = string(v)
	}

	if len(invalidKeys) > 0 {
		return nil, errors.NewIncompleteCredentialError(invalidKeys...)
	}

	return result, nil
}
