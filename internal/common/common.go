// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
			OperatorNamespace = ns
		} else {
			OperatorNamespace = v1.NamespaceDefault
		}
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
	case *secretsv1alpha1.VaultAuthBackend:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1alpha1.VaultKubernetesAuthBackend:
		authRef = o.Spec.VaultAuthRef
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1alpha1.VaultKubernetesAuthBackendRole:
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
	authObj, err := GetVaultAuthWithRetry(ctx, c, authName, time.Millisecond*500, 60)
	if err != nil {
		return nil, types.NamespacedName{}, err
	}
	return authObj, target, nil
}

func GetVaultConnection(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultConnection, error) {
	var obj secretsv1alpha1.VaultConnection
	if err := c.Get(ctx, key, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

func GetVaultConnectionWithRetry(ctx context.Context, c client.Client, key types.NamespacedName, delay time.Duration, max uint64) (*secretsv1alpha1.VaultConnection, error) {
	var obj secretsv1alpha1.VaultConnection
	if err := getWithRetry(ctx, c, key, &obj, delay, max); err != nil {
		return nil, err
	}

	return &obj, nil
}

func GetVaultAuth(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1alpha1.VaultAuth, error) {
	var obj secretsv1alpha1.VaultAuth
	if err := c.Get(ctx, key, &obj); err != nil {
		return nil, err
	}

	setVaultConnectionRef(&obj)
	return &obj, nil
}

func GetVaultAuthWithRetry(ctx context.Context, c client.Client, key types.NamespacedName, delay time.Duration, max uint64) (*secretsv1alpha1.VaultAuth, error) {
	var obj secretsv1alpha1.VaultAuth
	if err := getWithRetry(ctx, c, key, &obj, delay, max); err != nil {
		return nil, err
	}

	setVaultConnectionRef(&obj)
	return &obj, nil
}

func setVaultConnectionRef(obj *secretsv1alpha1.VaultAuth) {
	if obj.Namespace == OperatorNamespace && obj.Name == consts.NameDefault && obj.Spec.VaultConnectionRef == "" {
		obj.Spec.VaultConnectionRef = consts.NameDefault
	}
}

func getWithRetry(ctx context.Context, c client.Client, key types.NamespacedName, obj client.Object, delay time.Duration, max uint64) error {
	bo := backoff.WithMaxRetries(backoff.NewConstantBackOff(delay), max)
	return backoff.Retry(func() error {
		err := c.Get(ctx, key, obj)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return err
			} else {
				return backoff.Permanent(err)
			}
		}
		return nil
	}, bo)
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

func FindVaultAuthByUID(ctx context.Context, c client.Client, namespace string, uid types.UID, generation int64) (*secretsv1alpha1.VaultAuth, error) {
	var auths secretsv1alpha1.VaultAuthList
	var opts []client.ListOption
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := c.List(ctx, &auths, opts...); err != nil {
		return nil, err
	}

	for _, item := range auths.Items {
		if item.GetUID() == uid && item.GetGeneration() == generation {
			setVaultConnectionRef(&item)
			return &item, nil
		}
	}

	return nil, fmt.Errorf("object not found")
}

func FindVaultConnectionByUID(ctx context.Context, c client.Client, namespace string, uid types.UID, generation int64) (*secretsv1alpha1.VaultConnection, error) {
	var auths secretsv1alpha1.VaultConnectionList
	var opts []client.ListOption
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := c.List(ctx, &auths, opts...); err != nil {
		return nil, err
	}

	for _, item := range auths.Items {
		if item.GetUID() == uid && item.GetGeneration() == generation {
			return &item, nil
		}
	}

	return nil, fmt.Errorf("object not found")
}

// FindVaultAuthForStorageEncryption returns VaultAuth resource labeled with `cacheEncryption=true`, and is found in the Operator's namespace.
// If none or more than one resource is found, an error will be returned.
// The resulting resource must have a valid StorageEncryption configured.
func FindVaultAuthForStorageEncryption(ctx context.Context, c client.Client) (*secretsv1alpha1.VaultAuth, error) {
	opts := []client.ListOption{
		client.InNamespace(OperatorNamespace),
		client.MatchingLabels{
			"cacheStorageEncryption": "true",
		},
	}
	var auths secretsv1alpha1.VaultAuthList
	if err := c.List(ctx, &auths, opts...); err != nil {
		return nil, err
	}

	if len(auths.Items) != 1 {
		return nil, fmt.Errorf("invalid VaultAuth for storage encryption, found=%d, required=1", len(auths.Items))
	}

	result := auths.Items[0]
	if result.Spec.StorageEncryption == nil {
		return nil, fmt.Errorf("invalid VaultAuth %s for storage encryption, no StorageEncryption configured",
			client.ObjectKeyFromObject(&result))
	}

	return &result, nil
}
