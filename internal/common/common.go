// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
)

// operatorNamespace of the current operator instance, set in init()
var OperatorNamespace string

func init() {
	var err error
	OperatorNamespace, err = utils.GetCurrentNamespace()
	if err != nil {
		OperatorNamespace = v1.NamespaceDefault
	}
}

func GetVaultAuthAndTarget(ctx context.Context, c client.Client, obj client.Object) (*secretsv1alpha1.VaultAuth, types.NamespacedName, error) {
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
	case *secretsv1alpha1.VaultDynamicSecret:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1alpha1.VaultTransit:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	default:
		return nil, types.NamespacedName{}, fmt.Errorf("unsupported type %T", o)
	}

	var authName types.NamespacedName
	if authRef == "" {
		// if no authRef configured we try and grab the 'default' from the
		// Operator's current namespace.
		authName = types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.NameDefault,
		}
	} else {
		authName = types.NamespacedName{
			Namespace: target.Namespace,
			Name:      authRef,
		}
	}
	auth, err := GetVaultAuth(ctx, c, authName)
	if err != nil {
		return nil, types.NamespacedName{}, err
	}
	return auth, target, nil
}

func GetVaultConnection(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultConnection, error) {
	connObj := &secretsv1alpha1.VaultConnection{}
	if err := c.Get(ctx, key, connObj); err != nil {
		return nil, err
	}
	return connObj, nil
}

func GetVaultAuth(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultAuth, error) {
	authObj := &secretsv1alpha1.VaultAuth{}
	if err := c.Get(ctx, key, authObj); err != nil {
		return nil, err
	}
	if authObj.Namespace == OperatorNamespace && authObj.Name == consts.NameDefault && authObj.Spec.VaultConnectionRef == "" {
		authObj.Spec.VaultConnectionRef = consts.NameDefault
	}
	return authObj, nil
}

func GetVaultTransit(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultTransit, error) {
	o := &secretsv1alpha1.VaultTransit{}
	if err := c.Get(ctx, key, o); err != nil {
		return nil, err
	}
	return o, nil
}

// GetConnectionNamespacedName returns the NamespacedName for the VaultAuth's configured
// vaultConnectionRef.
// If the vaultConnectionRef is empty then defaults Namespace and Name will be returned.
func GetConnectionNamespacedName(a *secretsv1alpha1.VaultAuth) (types.NamespacedName, error) {
	if a.Spec.VaultConnectionRef == "" {
		if OperatorNamespace == "" {
			return types.NamespacedName{}, fmt.Errorf("operator's default namespace is not set, this is a bug")
		}
		return types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.NameDefault,
		}, nil
	}

	// the VaultConnection CR must be in the same namespace as its VaultAuth.
	return types.NamespacedName{
		Namespace: a.Namespace,
		Name:      a.Spec.VaultConnectionRef,
	}, nil
}
