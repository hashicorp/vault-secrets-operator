// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentialproviders

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

type JwtCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	tokenSecret       *corev1.Secret
	uid               types.UID
}

func (l *JwtCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *JwtCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *JwtCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	if l.authObj.Spec.Jwt.ServiceAccount != "" {
		sa, err := l.getServiceAccount(ctx, client)
		if err != nil {
			return err
		}
		l.uid = sa.UID
	} else if l.authObj.Spec.Jwt.TokenSecretKeySelector != nil &&
		l.authObj.Spec.Jwt.TokenSecretKeySelector.Name != "" &&
		l.authObj.Spec.Jwt.TokenSecretKeySelector.Key != "" {
		var err error
		l.tokenSecret, err = l.getTokenSecret(ctx, client)
		if err != nil {
			return err
		}
		l.uid = l.tokenSecret.ObjectMeta.UID
	} else {
		return fmt.Errorf("either serviceAccount or jwt token secret key selector is required to " +
			"retrieve credentials to authenticate to Vault's jwt authentication backend")
	}

	return nil
}

func (l *JwtCredentialProvider) getServiceAccount(ctx context.Context, client ctrlclient.Client) (*corev1.ServiceAccount, error) {
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.Jwt.ServiceAccount,
	}
	sa := &corev1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func (l *JwtCredentialProvider) getTokenSecret(ctx context.Context, client ctrlclient.Client) (*corev1.Secret, error) {
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.Jwt.TokenSecretKeySelector.Name,
	}
	secret := &corev1.Secret{}
	if err := client.Get(ctx, key, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func (l *JwtCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

	if l.authObj.Spec.Jwt.ServiceAccount != "" {
		sa, err := l.getServiceAccount(ctx, client)
		if err != nil {
			logger.Error(err, "Failed to get service account")
			return nil, err
		}

		tr, err := l.requestSAToken(ctx, client, sa)
		if err != nil {
			logger.Error(err, "Failed to get service account token")
			return nil, err
		}

		// credentials needed for Jwt auth
		return map[string]interface{}{
			"role": l.authObj.Spec.Jwt.Role,
			"jwt":  tr.Status.Token,
		}, nil
	}

	return map[string]interface{}{
		"role": l.authObj.Spec.Jwt.Role,
		"jwt":  string(l.tokenSecret.Data[l.authObj.Spec.Jwt.TokenSecretKeySelector.Key]),
	}, nil
}

// requestSAToken for the provided ServiceAccount.
func (l *JwtCredentialProvider) requestSAToken(ctx context.Context, client ctrlclient.Client, sa *corev1.ServiceAccount) (*authv1.TokenRequest, error) {
	tr := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: TokenGenerateName,
		},
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: pointer.Int64(l.authObj.Spec.Jwt.TokenExpirationSeconds),
			Audiences:         l.authObj.Spec.Jwt.TokenAudiences,
		},
		Status: authv1.TokenRequestStatus{},
	}

	if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
		return nil, err
	}

	return tr, nil
}
