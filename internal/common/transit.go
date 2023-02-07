// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func GetVaultTransit(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultTransit, error) {
	o := &secretsv1alpha1.VaultTransit{}
	if err := c.Get(ctx, key, o); err != nil {
		return nil, err
	}
	return o, nil
}
