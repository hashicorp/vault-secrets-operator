package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

// AuthLogin
type AuthLogin interface {
	MountPath() string
	LoginPath() string
	Login(context.Context, *api.Client) (*api.Secret, error)
	GetK8SNamespace() string
	SetK8SNamespace(string)
	Validate() error
}

type KubernetesAuth struct {
	client crclient.Client
	va     *v1alpha1.VaultAuth
	vc     *v1alpha1.VaultConnection
	sans   string
}

func (l *KubernetesAuth) SetK8SNamespace(ns string) {
	l.sans = ns
}

// Login to Vault with the related VaultAuth and VaultConnection.
func (l *KubernetesAuth) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	// TODO: add support for token caching
	logger := log.FromContext(ctx)
	n := types.NamespacedName{
		Namespace: l.GetK8SNamespace(),
		Name:      l.va.Spec.Kubernetes.ServiceAccount,
	}

	sa := &corev1.ServiceAccount{}
	if err := l.client.Get(ctx, n, sa); err != nil {
		logger.Error(err, "Failed to get service account")
		return nil, err
	}

	logger.Info(fmt.Sprintf("Authenticating with ServiceAccount %q", sa))
	tr, err := l.requestSAToken(ctx, sa)
	if err != nil {
		return nil, err
	}

	resp, err := client.Logical().WriteWithContext(
		ctx,
		l.LoginPath(),
		map[string]interface{}{
			"role": l.va.Spec.Kubernetes.Role,
			"jwt":  tr.Status.Token,
		})
	if err != nil {
		logger.Error(err, "Failed to authenticate to Vault")
		return nil, err
	}

	logger.Info("Successfully authenticated to Vault", "path", l.LoginPath())
	return resp, nil
}

// requestSAToken for the provided ServiceAccount.
func (l *KubernetesAuth) requestSAToken(ctx context.Context, sa *corev1.ServiceAccount) (*authv1.TokenRequest, error) {
	logger := log.FromContext(ctx)
	tr := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: l.va.Spec.Kubernetes.TokenGenerateName,
		},
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: pointer.Int64(l.va.Spec.Kubernetes.TokenExpirationSeconds),
			Audiences:         l.va.Spec.Kubernetes.TokenAudiences,
		},
		Status: authv1.TokenRequestStatus{},
	}

	if err := l.client.SubResource("token").Create(ctx, sa, tr); err != nil {
		logger.Error(err, "Failed to create token from service account", "serviceaccount", sa.String())
		return nil, err
	}
	// TODO: remove (reveals secrets)
	logger.Info("Got token request", "tr", tr, "status", tr)

	return tr, nil
}

func (l *KubernetesAuth) MountPath() string {
	return l.va.Spec.Mount
}

func (l *KubernetesAuth) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

func (l *KubernetesAuth) GetK8SNamespace() string {
	return l.sans
}

func (l *KubernetesAuth) Validate() error {
	var err error
	if l.va == nil {
		err = multierror.Append(err, fmt.Errorf("VaultAuth is not set"))
	} else {
		if l.va.Spec.Kubernetes == nil {
			err = multierror.Append(err, fmt.Errorf("VaultAuth.Spec.Kubernetes is not set"))
		}
	}
	if l.client == nil {
		err = multierror.Append(err, fmt.Errorf("controller-runtime Client is not set"))
	}

	if len(l.GetK8SNamespace()) == 0 {
		err = multierror.Append(err, fmt.Errorf("kubernetes namespace is not set"))
	}

	return err
}

// NewAuthLogin from a VaultAuth and VaultConnection spec.
func NewAuthLogin(c crclient.Client, va *v1alpha1.VaultAuth, k8sNamespace string) (AuthLogin, error) {
	switch va.Spec.Method {
	case "kubernetes":
		a := &KubernetesAuth{
			client: c,
			va:     va,
		}
		a.SetK8SNamespace(k8sNamespace)
		if err := a.Validate(); err != nil {
			return nil, err
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unsupported login method %q for AuthLogin", va.Spec.Method)
	}
}
