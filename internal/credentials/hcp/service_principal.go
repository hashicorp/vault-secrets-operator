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
	ProviderSecretClientKey        = "clientKey"
)

var _ CredentialProviderHCP = (*ServicePrincipleCredentialProvider)(nil)

type ServicePrincipleCredentialProvider struct {
	authObj           *secretsv1beta1.HCPAuth
	providerNamespace string
	uid               types.UID
}

func (l *ServicePrincipleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *ServicePrincipleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *ServicePrincipleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client,
	authObj *secretsv1beta1.HCPAuth, providerNamespace string,
) error {
	logger := log.FromContext(ctx)
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	// We use the UID of the secret which holds the AppRole Role's secret_id for the provider UID
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

func (l *ServicePrincipleCredentialProvider) GetCreds(ctx context.Context,
	client ctrlclient.Client,
) (map[string]interface{}, error) {
	objKey := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.ServicePrincipal.SecretRef,
	}

	secret, err := helpers.GetSecret(ctx, client, objKey)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", errors.InvalidCredentialDataError, err)
	}

	keys := []string{ProviderSecretClientKey, ProviderSecretClientID}
	result := make(map[string]interface{}, len(keys))
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
