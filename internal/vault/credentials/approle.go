// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

var _ CredentialProvider = (*AppRoleCredentialProvider)(nil)

type AppRoleCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *AppRoleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *AppRoleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *AppRoleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	logger := log.FromContext(ctx)
	l.authObj = authObj
	l.providerNamespace = providerNamespace
	secret, err := getSecret(ctx, client, l.providerNamespace, l.authObj.Spec.AppRole.SecretKeyRef.Name)
	if err != nil {
		logger.Error(err, "Failed to get secret", "secret_name", l.authObj.Spec.AppRole.SecretKeyRef.Name)
		return err
	}
	l.uid = secret.UID
	return nil
}

func (l *AppRoleCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)
	// Fetch the secret_id each time we call GetCreds in case the secret_id has changed since
	// the last time the client token was generated. In the case of AppRole this is assumed to be common.
	secretID, err := l.getSecretID(ctx, client)
	if err != nil {
		logger.Error(err, "Failed to get secret_id", "role_id", l.authObj.Spec.AppRole.RoleID)
		return nil, err
	}
	// credentials needed for AppRole auth
	creds := map[string]interface{}{
		"role_id":   l.authObj.Spec.AppRole.RoleID,
		"secret_id": secretID,
	}
	return creds, nil
}

func (l *AppRoleCredentialProvider) getSecretID(ctx context.Context, client ctrlclient.Client) (string, error) {
	logger := log.FromContext(ctx)

	secret, err := getSecret(ctx, client, l.authObj.Namespace, l.authObj.Spec.AppRole.SecretKeyRef.Name)
	if err != nil {
		logger.Error(err, "Failed to get secret when fetching secret_id", "role_id", l.authObj.Spec.AppRole.RoleID)
		return "", err
	}
	secretID := string(secret.Data[l.authObj.Spec.AppRole.SecretKeyRef.Key])
	if secretID == "" {
		return "", fmt.Errorf("Invalid key reference for secret_id, empty data")
	}
	return secretID, nil
}
