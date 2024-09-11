// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"

	v12 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	v13 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/common"
)

const TokenGenerateName = "vso-"

// RequestSAToken for the provided ServiceAccount, expirationSeconds, and audiences
func RequestSAToken(ctx context.Context, client client.Client, sa *v1.ServiceAccount, expirationSeconds int64, audiences []string) (*v12.TokenRequest, error) {
	tr := &v12.TokenRequest{
		ObjectMeta: v13.ObjectMeta{
			GenerateName: TokenGenerateName,
		},
		Spec: v12.TokenRequestSpec{
			ExpirationSeconds: ptr.To(expirationSeconds),
			Audiences:         audiences,
		},
		Status: v12.TokenRequestStatus{},
	}

	if err := client.SubResource("token").Create(ctx, sa, tr); err != nil {
		return nil, err
	}

	return tr, nil
}

func GetServiceAccount(ctx context.Context, client client.Client, key client.ObjectKey) (*v1.ServiceAccount, error) {
	if err := common.ValidateObjectKey(key); err != nil {
		return nil, err
	}
	sa := &v1.ServiceAccount{}
	if err := client.Get(ctx, key, sa); err != nil {
		return nil, err
	}

	return sa, nil
}
