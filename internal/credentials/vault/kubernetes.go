// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

var _ CredentialProvider = (*KubernetesCredentialProvider)(nil)

type KubernetesCredentialProvider struct {
	authObj           *secretsv1beta1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func NewKubernetesCredentialProvider(authObj *secretsv1beta1.VaultAuth, providerNamespace string,
	uid types.UID,
) *KubernetesCredentialProvider {
	return &KubernetesCredentialProvider{
		authObj,
		providerNamespace,
		uid,
	}
}

func (l *KubernetesCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *KubernetesCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *KubernetesCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	sa, err := l.getServiceAccount(ctx, client)
	if err != nil {
		return err
	}

	l.uid = sa.UID

	return nil
}

func (l *KubernetesCredentialProvider) getServiceAccount(ctx context.Context, client ctrlclient.Client) (*corev1.ServiceAccount, error) {
	a, err := common.GetKubernetesServiceAccountNamespacedName(l.authObj.Spec.Kubernetes, l.providerNamespace)
	if err != nil {
		return nil, err
	}
	key := ctrlclient.ObjectKey{
		Namespace: a.Namespace,
		Name:      a.Name,
	}
	sa := &corev1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func (l *KubernetesCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

	sa, err := l.getServiceAccount(ctx, client)
	if err != nil {
		logger.Error(err, "Failed to get service account")
		return nil, err
	}

	tr, err := helpers.RequestSAToken(ctx, client, sa, l.authObj.Spec.Kubernetes.TokenExpirationSeconds, l.authObj.Spec.Kubernetes.TokenAudiences)
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
