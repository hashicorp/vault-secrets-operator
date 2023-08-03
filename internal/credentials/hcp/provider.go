// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package hcp

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
)

type CredentialProviderHCP interface {
	provider.CredentialProviderBase
	Init(context.Context, client.Client, *v1beta1.HCPAuth, string) error
}
