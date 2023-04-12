package credentialproviders

import (
	"context"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var _ vault.CredentialProvider = (*KubernetesCredentialProvider)(nil)

type KubernetesCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func NewKubernetesCredentialProvider(authObj *secretsv1alpha1.VaultAuth, providerNamespace string,
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

func (l *KubernetesCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
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

func (l *KubernetesCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
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
func (l *KubernetesCredentialProvider) requestSAToken(ctx context.Context, client ctrlclient.Client, sa *corev1.ServiceAccount) (*authv1.TokenRequest, error) {
	tr := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: vault.TokenGenerateName,
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
