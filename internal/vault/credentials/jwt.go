// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

var _ CredentialProvider = (*JWTCredentialProvider)(nil)

type JWTCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	tokenSecret       *corev1.Secret
	uid               types.UID
}

func (l *JWTCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *JWTCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *JWTCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	if l.authObj.Spec.JWT.ServiceAccount != "" {
		sa, err := l.getServiceAccount(ctx, client)
		if err != nil {
			return err
		}
		l.uid = sa.UID
	} else if l.authObj.Spec.JWT.SecretRef != "" {
		var err error
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.JWT.SecretRef,
		}
		l.tokenSecret, err = getSecret(ctx, client, key)
		if err != nil {
			return err
		}
		l.uid = l.tokenSecret.ObjectMeta.UID
	} else {
		return fmt.Errorf("either serviceAccount or JWT token secret key selector is required to " +
			"retrieve credentials to authenticate to Vault's JWT authentication backend")
	}

	return nil
}

func (l *JWTCredentialProvider) getServiceAccount(ctx context.Context, client ctrlclient.Client) (*corev1.ServiceAccount, error) {
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.JWT.ServiceAccount,
	}
	sa := &corev1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func (l *JWTCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

	if l.authObj.Spec.JWT.ServiceAccount != "" {
		sa, err := l.getServiceAccount(ctx, client)
		if err != nil {
			logger.Error(err, "Failed to get service account")
			return nil, err
		}

		tr, err := requestSAToken(ctx, client, sa, l.authObj.Spec.JWT.TokenExpirationSeconds, l.authObj.Spec.JWT.TokenAudiences)
		if err != nil {
			logger.Error(err, "Failed to get service account token")
			return nil, err
		}

		// credentials needed for JWT auth
		return map[string]interface{}{
			"role": l.authObj.Spec.JWT.Role,
			"jwt":  tr.Status.Token,
		}, nil
	}

	var err error
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.JWT.SecretRef,
	}
	l.tokenSecret, err = getSecret(ctx, client, key)
	if err != nil {
		return nil, err
	}
	if l.tokenSecret.Data[ProviderSecretKeyJWT] == nil {
		err = fmt.Errorf("unable to get Secret data from Secret")
		logger.Error(err, "Failed to get secret_id from secret", "secret_name", l.authObj.Spec.AppRole.SecretRef)
		return nil, err
	}
	return map[string]interface{}{
		"role": l.authObj.Spec.JWT.Role,
		"jwt":  string(l.tokenSecret.Data[ProviderSecretKeyJWT]),
	}, nil
}
