// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type CredentialProviderBase interface {
	GetUID() types.UID
	GetNamespace() string
	GetCreds(context.Context, ctrlclient.Client) (map[string]interface{}, error)
}
