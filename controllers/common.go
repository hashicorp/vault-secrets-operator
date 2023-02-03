// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

const (
	reasonAccepted          = "Accepted"
	reasonVaultClientError  = "VaultClientError"
	reasonVaultStaticSecret = "VaultStaticSecretError"
	reasonK8sClientError    = "K8sClientError"
)

// operatorNamespace of the current operator instance, set in init()
var operatorNamespace string

func init() {
	var err error
	operatorNamespace, err = utils.GetCurrentNamespace()
	if err != nil {
		operatorNamespace = metav1.NamespaceDefault
	}
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
		return nil, fmt.Errorf("unsupported type %T", o)
	}

	var authName types.NamespacedName
	if authRef == "" {
		// if no authRef configured we try and grab the 'default' from the
		// Operator's current namespace.
		authName = types.NamespacedName{
			Namespace: operatorNamespace,
			Name:      consts.NameDefault,
		}
	} else {
		authName = types.NamespacedName{
			Namespace: target.Namespace,
			Name:      authRef,
		}
	}
	auth, err := getVaultAuth(ctx, c, authName)
	if err != nil {
		return nil, err
	}

	connName, err := getConnectionNamespacedName(auth)
	if err != nil {
		return nil, err
	}

	conn, err := getVaultConnection(ctx, c, connName)
	if err != nil {
		return nil, err
	}

	authLogin, err := vault.NewAuthLogin(c, auth, target.Namespace)
	if err != nil {
		return nil, err
	}

	return &vault.VaultClientConfig{
		Address:         conn.Spec.Address,
		SkipTLSVerify:   conn.Spec.SkipTLSVerify,
		TLSServerName:   conn.Spec.TLSServerName,
		VaultNamespace:  auth.Spec.Namespace,
		CACertSecretRef: conn.Spec.CACertSecretRef,
		K8sNamespace:    target.Namespace,
		AuthLogin:       authLogin,
	}, nil
}

func getVaultConnection(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultConnection, error) {
	connObj := &secretsv1alpha1.VaultConnection{}
	if err := c.Get(ctx, key, connObj); err != nil {
		return nil, err
	}
	return connObj, nil
}

func getVaultAuth(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultAuth, error) {
	authObj := &secretsv1alpha1.VaultAuth{}
	if err := c.Get(ctx, key, authObj); err != nil {
		return nil, err
	}
	if authObj.Namespace == operatorNamespace && authObj.Name == consts.NameDefault && authObj.Spec.VaultConnectionRef == "" {
		authObj.Spec.VaultConnectionRef = consts.NameDefault
	}
	return authObj, nil
}

func getVaultClient(ctx context.Context, vaultConfig *vault.VaultClientConfig, client client.Client) (*api.Client, error) {
	c, err := vault.MakeVaultClient(ctx, vaultConfig, client)
	if err != nil {
		return nil, err
	}

	if vaultConfig.VaultNamespace != "" {
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

func ignoreUpdatePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Ignore updates to CR status in which case metadata.Generation does not change
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
	}
}

// getConnectionNamespacedName returns the NamespacedName for the VaultAuth's configured
// vaultConnectionRef.
// If the vaultConnectionRef is empty then defaults Namespace and Name will be returned.
func getConnectionNamespacedName(a *secretsv1alpha1.VaultAuth) (types.NamespacedName, error) {
	if a.Spec.VaultConnectionRef == "" {
		if operatorNamespace == "" {
			return types.NamespacedName{}, fmt.Errorf("operator's default namespace is not set, this is a bug")
		}
		return types.NamespacedName{
			Namespace: operatorNamespace,
			Name:      consts.NameDefault,
		}, nil
	}

	// the VaultConnection CR must be in the same namespace as its VaultAuth.
	return types.NamespacedName{
		Namespace: a.Namespace,
		Name:      a.Spec.VaultConnectionRef,
	}, nil
}
