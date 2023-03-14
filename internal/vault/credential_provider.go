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
)

const (
	tokenGenerateName               = "vso-"
	providerMethodKubernetes string = "kubernetes"
)

var providerMethodsSupported = []string{providerMethodKubernetes}

type CredentialProvider interface {
	Init(ctx context.Context, client ctrlclient.Client, object *secretsv1alpha1.VaultAuth, providerNamespace string) error
	GetUID() types.UID
	GetNamespace() string
	GetCreds(context.Context, ctrlclient.Client) (map[string]interface{}, error)
}

var _ CredentialProvider = (*kubernetesCredentialProvider)(nil)

type kubernetesCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *kubernetesCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *kubernetesCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *kubernetesCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	sa, err := l.getServiceAccount(ctx, client)
	if err != nil {
		return err
	}

	l.uid = sa.UID

	return nil
}

func (l *kubernetesCredentialProvider) getServiceAccount(ctx context.Context, client ctrlclient.Client) (*corev1.ServiceAccount, error) {
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
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

func NewCredentialProvider(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) (CredentialProvider, error) {
	switch authObj.Spec.Method {
	case providerMethodKubernetes:
		provider := &kubernetesCredentialProvider{}
		if err := provider.Init(ctx, client, authObj, providerNamespace); err != nil {
			return nil, err
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method %s", authObj.Spec.Method)
	}
}
