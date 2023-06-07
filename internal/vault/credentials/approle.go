// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

var _ CredentialProvider = (*AppRoleCredentialProvider)(nil)

type AppRoleCredentialProvider struct {
	authObj           *secretsv1beta1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *AppRoleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *AppRoleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *AppRoleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) error {
	logger := log.FromContext(ctx)
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	// We use the UID of the secret which holds the AppRole Role's secret_id for the provider UID
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.AppRole.SecretRef,
	}
	secret, err := getSecret(ctx, client, key)
	if err != nil {
		logger.Error(err, "Failed to get secret", "secret_name", l.authObj.Spec.AppRole.SecretRef)
		return err
	}
	l.uid = secret.UID
	return nil
}

func (l *AppRoleCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)
	// Fetch the AppRole Role's SecretID from the Kubernetes Secret each time there is a call to
	// GetCreds in case the SecretID has changed since the last time the client token was
	// generated. In the case of AppRole this is assumed to be common.
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.AppRole.SecretRef,
	}
	secret, err := getSecret(ctx, client, key)
	if err != nil {
		logger.Error(err, "Failed to get secret", "secret_name", l.authObj.Spec.AppRole.SecretRef)
		return nil, err
	}
	if secretID, ok := secret.Data[ProviderSecretKeyAppRole]; !ok {
		err = fmt.Errorf("no key %q found in secret", ProviderSecretKeyAppRole)
		logger.Error(err, "Failed to get secretID from secret", "secret_name",
			l.authObj.Spec.AppRole.SecretRef)
		return nil, err
	} else if len(secretID) == 0 {
		err = fmt.Errorf("no data found in secret key %q", ProviderSecretKeyAppRole)
		logger.Error(err, "Failed to get secretID from secret", "secret_name",
			l.authObj.Spec.AppRole.SecretRef)
		return nil, err
	} else {
		// credentials needed for AppRole auth
		return map[string]interface{}{
			"role_id":   l.authObj.Spec.AppRole.RoleID,
			"secret_id": string(secretID),
		}, nil
	}
}
