// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package config

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	v1alpha12 "github.com/hashicorp/vault-secrets-operator/internal/vault"
)

func GetVaultConfig(ctx context.Context, c client.Client, obj client.Object) (*v1alpha12.ClientConfig, error) {
	va, target, err := common.GetVaultAuthAndTarget(ctx, c, obj)
	if err != nil {
		return nil, err
	}

	connName, err := common.GetConnectionNamespacedName(va)
	if err != nil {
		return nil, err
	}

	conn, err := common.GetVaultConnection(ctx, c, connName)
	if err != nil {
		return nil, err
	}

	config := &v1alpha12.ClientConfig{
		Address:         conn.Spec.Address,
		SkipTLSVerify:   conn.Spec.SkipTLSVerify,
		TLSServerName:   conn.Spec.TLSServerName,
		VaultNamespace:  va.Spec.Namespace,
		CACertSecretRef: conn.Spec.CACertSecretRef,
		K8sNamespace:    target.Namespace,
	}

	return config, nil
}
