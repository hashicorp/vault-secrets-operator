// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// OperatorNamespace of the current operator instance, set in init()
// TODO: reconsider using a global here.
var OperatorNamespace string

func init() {
	operatorNamespace, err := utils.GetCurrentNamespace()
	if err != nil {
		operatorNamespace = "default"
	}
	OperatorNamespace = operatorNamespace
}

func getVaultConfig(ctx context.Context, c client.Client, obj client.Object) (*vault.VaultClientConfig, error) {
	var authRef string
	var target types.NamespacedName
	switch o := obj.(type) {
	case *secretsv1alpha1.VaultPKISecret:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1alpha1.VaultStaticSecret:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	default:
		return nil, fmt.Errorf("unsupport type %T", o)
	}

	var err error
	var va *secretsv1alpha1.VaultAuth
	if len(authRef) == 0 {
		// if no authRef configured we try and grab the 'default' from the
		// Operator's namespace.
		va, err = getVaultAuth(ctx, c, types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.DefaultNameVaultAuth,
		})
	} else {
		va, err = getVaultAuth(ctx, c, types.NamespacedName{
			Namespace: target.Namespace,
			Name:      authRef,
		})
	}
	if err != nil {
		return nil, err
	}

	connNsn, err := va.GetConnectionNamespacedName()
	if err != nil {
		return nil, err
	}

	vc, err := getVaultConnection(ctx, c, connNsn)
	if err != nil {
		return nil, err
	}

	// TODO: fix weirdness here
	authLogin, err := vault.NewAuthLogin(c, va, target.Namespace)
	if err != nil {
		return nil, err
	}

	config, err := newVaultConfig(target.Namespace, va, vc)
	if err != nil {
		return nil, err
	}
	config.SetAuthLogin(authLogin)

	return config, nil
}

func newVaultConfig(ns string, a *secretsv1alpha1.VaultAuth, c *secretsv1alpha1.VaultConnection) (*vault.VaultClientConfig, error) {
	return &vault.VaultClientConfig{
		CACertSecretRef: c.Spec.CACertSecretRef,
		K8sNamespace:    ns,
		Address:         c.Spec.Address,
		SkipTLSVerify:   c.Spec.SkipTLSVerify,
		TLSServerName:   c.Spec.TLSServerName,
		VaultNamespace:  a.Spec.Namespace,
	}, nil
}

func getVaultConnection(ctx context.Context, c client.Client, nameAndNamespace types.NamespacedName) (*secretsv1alpha1.VaultConnection, error) {
	connObj := &secretsv1alpha1.VaultConnection{}
	if err := c.Get(ctx, nameAndNamespace, connObj); err != nil {
		return nil, err
	}
	return connObj, nil
}

func getVaultAuth(ctx context.Context, c client.Client, nameAndNamespace types.NamespacedName) (*secretsv1alpha1.VaultAuth, error) {
	authObj := &secretsv1alpha1.VaultAuth{}
	if err := c.Get(ctx, nameAndNamespace, authObj); err != nil {
		return nil, err
	}
	return authObj, nil
}

func getVaultClient(ctx context.Context, vaultConfig *vault.VaultClientConfig, client client.Client) (*api.Client, error) {
	c, err := vault.MakeVaultClient(ctx, vaultConfig, client)
	if err != nil {
		return nil, err
	}

	if len(vaultConfig.VaultNamespace) > 0 {
		c.SetNamespace(vaultConfig.VaultNamespace)
	}

	if vaultConfig.AuthLogin == nil {
		return nil, fmt.Errorf("an AuthLogin must be specified")
	}

	resp, err := vaultConfig.AuthLogin.Login(ctx, c)
	if err != nil {
		return nil, err
	}

	c.SetToken(resp.Auth.ClientToken)

	return c, nil
}
