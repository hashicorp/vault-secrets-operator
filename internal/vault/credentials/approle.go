// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

type ApproleCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *ApproleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *ApproleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *ApproleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace
	l.uid = types.UID(uuid.New().String())
	return nil
}

func (l *ApproleCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)
	// Fetch the secret_id each time we call GetCreds in case the secret_id has changed since
	// the last time the client token was generated. In the case of approle this is assumed likely.
	sid, err := l.getSecretID(ctx, client)
	if err != nil || sid == "" {
		logger.Error(err, "Failed to get secret_id for ", "role_id", l.authObj.Spec.AppRole.RoleID)
		return nil, err
	}
	// credentials needed for approle auth
	creds := map[string]interface{}{
		"role_id":   l.authObj.Spec.AppRole.RoleID,
		"secret_id": sid,
	}
	return creds, nil
}

func (l *ApproleCredentialProvider) getSecretID(ctx context.Context, client ctrlclient.Client) (string, error) {
	logger := log.FromContext(ctx)
	key := ctrlclient.ObjectKey{
		Namespace: l.authObj.Namespace,
		Name:      l.authObj.Spec.AppRole.SecretKeyRef.Name,
	}
	secret := &corev1.Secret{}
	if err := client.Get(ctx, key, secret); err != nil {
		logger.Error(err, "Failed to get client when fetching secret_id ", "role_id", l.authObj.Spec.AppRole.RoleID)
		return "", err
	}
	secretID := string(secret.Data[l.authObj.Spec.AppRole.SecretKeyRef.Key])
	return secretID, nil
}
