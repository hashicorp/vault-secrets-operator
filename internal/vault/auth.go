// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
)

// AuthLogin
type AuthLogin interface {
	MountPath() string
	LoginPath() string
	Login(context.Context, *api.Client) (*api.Secret, error)
	GetK8SNamespace() string
	SetK8SNamespace(string)
	Validate() error
}

// NewAuthLogin from a VaultAuth and VaultConnection spec.
func NewAuthLogin(c crclient.Client, va *v1alpha1.VaultAuth, k8sNamespace string) (AuthLogin, error) {
	method := va.Spec.Method
	switch method {
	case "kubernetes":
		a := &KubernetesAuth{
			client:    c,
			vaultAuth: va,
		}
		a.SetK8SNamespace(k8sNamespace)
		if err := a.Validate(); err != nil {
			return nil, err
		}
		return a, nil
	default:
		return nil, fmt.Errorf("unsupported login method %q for AuthLogin %q", method, utils.GetNamespacedName(va))
	}
}
