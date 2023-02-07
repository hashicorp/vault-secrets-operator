// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

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
	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

const tokenGenerateName = "vault-secrets-operator"

type CredentialProvider interface {
	Init(ctx context.Context, client ctrlclient.Client, object ctrlclient.Object) error
	GetUID() types.UID
	GetCreds(context.Context, ctrlclient.Client) (map[string]interface{}, error)
}

var _ CredentialProvider = (*kubernetesCredentialProvider)(nil)

type kubernetesCredentialProvider struct {
	authObj *secretsv1alpha1.VaultAuth
	target  ctrlclient.ObjectKey
	uid     types.UID
}

func (l *kubernetesCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *kubernetesCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) error {
	authObj, target, err := common.GetVaultAuthAndTarget(ctx, client, obj)
	if err != nil {
		return err
	}

	l.authObj = authObj
	l.target = target
	sa, err := l.getServiceAccount(ctx, client)
	if err != nil {
		return err
	}

	l.uid = sa.UID

	return nil
}

func (l *kubernetesCredentialProvider) getServiceAccount(ctx context.Context, client ctrlclient.Client) (*corev1.ServiceAccount, error) {
	key := ctrlclient.ObjectKey{
		Namespace: l.target.Namespace,
		Name:      l.authObj.Spec.Kubernetes.ServiceAccount,
	}
	sa := &corev1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func (l *kubernetesCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

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

	// credentials needed for Kubernetes auth
	return map[string]interface{}{
		"role": l.authObj.Spec.Kubernetes.Role,
		"jwt":  tr.Status.Token,
	}, nil
}

// requestSAToken for the provided ServiceAccount.
func (l *kubernetesCredentialProvider) requestSAToken(ctx context.Context, client ctrlclient.Client, sa *corev1.ServiceAccount) (*authv1.TokenRequest, error) {
	tr := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: tokenGenerateName,
		},
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: pointer.Int64(l.authObj.Spec.Kubernetes.TokenExpirationSeconds),
			Audiences:         l.authObj.Spec.Kubernetes.TokenAudiences,
		},
		Status: authv1.TokenRequestStatus{},
	}

	if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
		return nil, err
	}

	return tr, nil
}

func NewCredentialProvider(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, method string) (CredentialProvider, error) {
	switch method {
	case "kubernetes":
		provider := &kubernetesCredentialProvider{}
		if err := provider.Init(ctx, client, obj); err != nil {
			return nil, err
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method %s", method)
	}
}
