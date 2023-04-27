// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentialproviders

import (
	"context"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
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
func getSecret(ctx context.Context, client ctrlclient.Client, namespace, name string) (*corev1.Secret, error) {
	key := ctrlclient.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
	secret := &corev1.Secret{}
	if err := client.Get(ctx, key, secret); err != nil {
		return nil, err
	}

	return secret, nil
}
