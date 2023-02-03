// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/api"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

const tokenGenerateName = "vault-secrets-operator"

var _ AuthLogin = (*KubernetesAuth)(nil)

// KubernetesAuth implements the AuthLogin interface to log in to Vault.
type KubernetesAuth struct {
	client    ctrlclient.Client
	vaultAuth *v1alpha1.VaultAuth
	vaultConn *v1alpha1.VaultConnection
	// serviceAccountNamespace to use when creating k8s tokens.
	serviceAccountNamespace string
}

// Login to Vault with the related VaultAuth and VaultConnection.
func (l *KubernetesAuth) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	// TODO: add support for token caching
	logger := log.FromContext(ctx)
	n := types.NamespacedName{
		Namespace: l.GetK8SNamespace(),
		Name:      l.vaultAuth.Spec.Kubernetes.ServiceAccount,
	}

	sa := &v1.ServiceAccount{}
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
			"role": l.vaultAuth.Spec.Kubernetes.Role,
			"jwt":  tr.Status.Token,
		})
	if err != nil {
		logger.Error(err, "Failed to authenticate to Vault")
		return nil, err
	}

	logger.Info("Successfully authenticated to Vault", "path", l.LoginPath())
	return resp, nil
}

func (l *KubernetesAuth) getSATokenRequest() (*authv1.TokenRequest, error) {
	return &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: tokenGenerateName,
		},
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: pointer.Int64(l.vaultAuth.Spec.Kubernetes.TokenExpirationSeconds),
			Audiences:         l.vaultAuth.Spec.Kubernetes.TokenAudiences,
		},
		Status: authv1.TokenRequestStatus{},
	}, nil
}

// requestSAToken for the provided ServiceAccount.
func (l *KubernetesAuth) requestSAToken(ctx context.Context, sa *v1.ServiceAccount) (*authv1.TokenRequest, error) {
	// TODO: add unit tests, currently being covered by integration tests.
	logger := log.FromContext(ctx)
	tr, err := l.getSATokenRequest()
	if err != nil {
		logger.Error(err, "Failed to create token request", "serviceaccount", sa.String())
		return nil, err
	}

	if err := l.client.SubResource("token").Create(ctx, sa, tr); err != nil {
		logger.Error(err, "Failed to create token from service account", "serviceaccount", sa.String())
		return nil, err
	}

	return tr, nil
}

// MountPath to the Vault authentication backend.
func (l *KubernetesAuth) MountPath() string {
	return l.vaultAuth.Spec.Mount
}

// LoginPath for authenticating to Vault.
func (l *KubernetesAuth) LoginPath() string {
	return fmt.Sprintf("auth/%s/login", l.MountPath())
}

// SetK8SNamespace to use for the login request.
func (l *KubernetesAuth) SetK8SNamespace(ns string) {
	l.serviceAccountNamespace = ns
}

// GetK8SNamespace for the login request.
func (l *KubernetesAuth) GetK8SNamespace() string {
	return l.serviceAccountNamespace
}

// Validate that the AuthLogin was properly initialized.
func (l *KubernetesAuth) Validate() error {
	var err error
	if l.vaultAuth == nil {
		err = multierror.Append(err, fmt.Errorf("VaultAuth is not set"))
	} else {
		if l.vaultAuth.Spec.Kubernetes == nil {
			err = multierror.Append(err, fmt.Errorf("VaultAuth.Spec.Kubernetes is not set"))
		}
	}
	if l.client == nil {
		err = multierror.Append(err, fmt.Errorf("controller-runtime Client is not set"))
	}

	if l.GetK8SNamespace() == "" {
		err = multierror.Append(err, fmt.Errorf("kubernetes namespace is not set"))
	}

	return err
}
