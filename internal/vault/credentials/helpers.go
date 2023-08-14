// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

// requestSAToken for the provided ServiceAccount, expirationSeconds, and audiences
func requestSAToken(ctx context.Context, client ctrlclient.Client, sa *corev1.ServiceAccount, expirationSeconds int64, audiences []string) (*authv1.TokenRequest, error) {
	tr := &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: TokenGenerateName,
		},
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: pointer.Int64(expirationSeconds),
			Audiences:         audiences,
		},
		Status: authv1.TokenRequestStatus{},
	}

	if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
		return nil, err
	}

	return tr, nil
}

// getSecret for the provided namespace and name
func getSecret(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.Secret, error) {
	if err := common.ValidateObjectKey(key); err != nil {
		return nil, err
	}
	secret := &corev1.Secret{}
	if err := client.Get(ctx, key, secret); err != nil {
		return nil, err
	}

	return secret, nil
}

func getServiceAccount(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.ServiceAccount, error) {
	if err := common.ValidateObjectKey(key); err != nil {
		return nil, err
	}
	sa := &corev1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}

	return sa, nil
}

func getConfigMap(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.ConfigMap, error) {
	if err := common.ValidateObjectKey(key); err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{}
	if err := client.Get(ctx, key, cm); err != nil {
		return nil, err
	}

	return cm, nil
}
