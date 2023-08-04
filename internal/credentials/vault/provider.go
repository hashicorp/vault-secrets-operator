// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
)

type CredentialProvider interface {
	provider.CredentialProviderBase
	Init(ctx context.Context, client client.Client, object *v1beta1.VaultAuth, providerNamespace string) error
}
