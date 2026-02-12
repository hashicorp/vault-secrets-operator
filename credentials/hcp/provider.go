// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package hcp

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/provider"
)

type CredentialProviderHCP interface {
	provider.CredentialProviderBase
	Init(context.Context, client.Client, *v1beta1.HCPAuth, string) error
}
