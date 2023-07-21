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
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
)

var (
	// OperatorNamespace of the current operator instance, set in init()
	OperatorNamespace                   string
	InvalidObjectKeyError               = fmt.Errorf("invalid objectKey")
	InvalidObjectKeyErrorEmptyName      = fmt.Errorf("%w, empty name", InvalidObjectKeyError)
	InvalidObjectKeyErrorEmptyNamespace = fmt.Errorf("%w, empty namespace", InvalidObjectKeyError)
)

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

func GetAuthAndTargetNamespacedName(obj client.Object) (types.NamespacedName, types.NamespacedName, error) {
	var authRef types.NamespacedName
	var target types.NamespacedName
	var authRefNamespace string

	switch o := obj.(type) {
	case *secretsv1beta1.VaultPKISecret:
		if o.Spec.VaultAuthRefNamespace == "" {
			authRefNamespace = o.Namespace
		} else {
			authRefNamespace = o.Spec.VaultAuthRefNamespace
		}
		authRef = types.NamespacedName{
			Namespace: authRefNamespace,
			Name:      o.Spec.VaultAuthRef,
		}
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1beta1.VaultStaticSecret:
		if o.Spec.VaultAuthRefNamespace == "" {
			authRefNamespace = o.Namespace
		} else {
			authRefNamespace = o.Spec.VaultAuthRefNamespace
		}
		authRef = types.NamespacedName{
			Namespace: authRefNamespace,
			Name:      o.Spec.VaultAuthRef,
		}
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	case *secretsv1beta1.VaultDynamicSecret:
		if o.Spec.VaultAuthRefNamespace == "" {
			authRefNamespace = o.Namespace
		} else {
			authRefNamespace = o.Spec.VaultAuthRefNamespace
		}
		authRef = types.NamespacedName{
			Namespace: authRefNamespace,
			Name:      o.Spec.VaultAuthRef,
		}
		target = types.NamespacedName{
			Namespace: o.Namespace,
			Name:      o.Name,
		}
	default:
		return types.NamespacedName{}, types.NamespacedName{}, fmt.Errorf("unsupported type %T", o)
	}

	if authRef.Name == "" {
		// if no authRef configured we try and grab the 'default' from the
		// Operator's current namespace.
		authRef = types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.NameDefault,
		}
	}
	return authRef, target, nil
}

func GetVaultAuthAndTarget(ctx context.Context, c client.Client, obj client.Object) (*secretsv1beta1.VaultAuth, types.NamespacedName, error) {
	authRef, target, err := GetAuthAndTargetNamespacedName(obj)
	if err != nil {
		return nil, types.NamespacedName{}, err
	}
	authObj, err := GetVaultAuthWithRetry(ctx, c, authRef, time.Millisecond*500, 60)
	if err != nil {
		return nil, types.NamespacedName{}, err
	}
	return authObj, target, nil
}

func GetVaultConnection(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1beta1.VaultConnection, error) {
	var obj secretsv1beta1.VaultConnection
	if err := c.Get(ctx, key, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

func GetVaultConnectionWithRetry(ctx context.Context, c client.Client, key types.NamespacedName, delay time.Duration, max uint64) (*secretsv1beta1.VaultConnection, error) {
	var obj secretsv1beta1.VaultConnection
	if err := getWithRetry(ctx, c, key, &obj, delay, max); err != nil {
		return nil, err
	}

	return &obj, nil
}

func GetVaultAuth(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1beta1.VaultAuth, error) {
	var obj secretsv1beta1.VaultAuth
	if err := c.Get(ctx, key, &obj); err != nil {
		return nil, err
	}

	setVaultConnectionRef(&obj)
	return &obj, nil
}

func GetVaultAuthWithRetry(ctx context.Context, c client.Client, key types.NamespacedName, delay time.Duration, max uint64) (*secretsv1beta1.VaultAuth, error) {
	var obj secretsv1beta1.VaultAuth
	if err := getWithRetry(ctx, c, key, &obj, delay, max); err != nil {
		return nil, err
	}

	setVaultConnectionRef(&obj)
	return &obj, nil
}

func setVaultConnectionRef(obj *secretsv1beta1.VaultAuth) {
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
func GetConnectionNamespacedName(a *secretsv1beta1.VaultAuth) (types.NamespacedName, error) {
	if a.Spec.VaultConnectionRef == "" {
		if OperatorNamespace == "" {
			return types.NamespacedName{}, fmt.Errorf("operator's default namespace is not set, this is a bug")
		}
		return types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.NameDefault,
		}, nil
	}

	// Use the NS of the AuthRef, unless it's overridden in the AuthRef Spec.
	var vaultConnectionRefNamespace string
	if a.Spec.VaultConnectionRefNamespace == "" {
		vaultConnectionRefNamespace = a.Namespace
	} else {
		vaultConnectionRefNamespace = a.Spec.VaultConnectionRefNamespace
	}

	return types.NamespacedName{
		Namespace: vaultConnectionRefNamespace,
		Name:      a.Spec.VaultConnectionRef,
	}, nil
}

func FindVaultAuthByUID(ctx context.Context, c client.Client, namespace string, uid types.UID, generation int64) (*secretsv1beta1.VaultAuth, error) {
	var auths secretsv1beta1.VaultAuthList
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

func FindVaultConnectionByUID(ctx context.Context, c client.Client, namespace string, uid types.UID, generation int64) (*secretsv1beta1.VaultConnection, error) {
	var auths secretsv1beta1.VaultConnectionList
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
func FindVaultAuthForStorageEncryption(ctx context.Context, c client.Client) (*secretsv1beta1.VaultAuth, error) {
	opts := []client.ListOption{
		client.InNamespace(OperatorNamespace),
		client.MatchingLabels{
			"cacheStorageEncryption": "true",
		},
	}
	var auths secretsv1beta1.VaultAuthList
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

// GetVaultNamespace for the Syncable Secret type object.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func GetVaultNamespace(obj client.Object) (string, error) {
	var ns string
	switch o := obj.(type) {
	case *secretsv1beta1.VaultPKISecret:
		ns = o.Spec.Namespace
	case *secretsv1beta1.VaultStaticSecret:
		ns = o.Spec.Namespace
	case *secretsv1beta1.VaultDynamicSecret:
		ns = o.Spec.Namespace
	default:
		return "", fmt.Errorf("unsupported type %T", o)
	}
	return ns, nil
}

func ValidateObjectKey(key ctrlclient.ObjectKey) error {
	if key.Name == "" {
		return InvalidObjectKeyErrorEmptyName
	}
	if key.Namespace == "" {
		return InvalidObjectKeyErrorEmptyNamespace
	}
	return nil
}
