// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hcp

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
)

// CredentialProviderHCP provides credentials for authenticating to HCP.
//
// Deprecated: HCP Vault Secrets support is deprecated and will be removed in a
// future release of the Vault Secrets Operator.
type CredentialProviderHCP interface {
	provider.CredentialProviderBase
	Init(context.Context, client.Client, *v1beta1.HCPAuth, string) error
}
