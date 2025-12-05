// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/common"
)

func GetConfigMap(ctx context.Context, client client.Client, key client.ObjectKey) (*v1.ConfigMap, error) {
	if err := common.ValidateObjectKey(key); err != nil {
		return nil, err
	}
	cm := &v1.ConfigMap{}
	if err := client.Get(ctx, key, cm); err != nil {
		return nil, err
	}

	return cm, nil
}
