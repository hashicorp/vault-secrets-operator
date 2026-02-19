// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
)

type CredentialProvider interface {
	provider.CredentialProviderBase
	Init(ctx context.Context, client client.Client, object *v1beta1.VaultAuth, providerNamespace string) error
}
