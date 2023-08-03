// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"context"
	"fmt"
	"os"
	"strings"
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

	m, err := NewSyncableSecretMetaData(obj)
	if err != nil {
		return types.NamespacedName{}, types.NamespacedName{}, fmt.Errorf("unsupported type %T", obj)
	}

	if m.AuthRef != "" {
		names := strings.Split(m.AuthRef, "/")
		if len(names) > 2 {
			return types.NamespacedName{}, types.NamespacedName{}, fmt.Errorf("invalid auth method name %s", m.AuthRef)
		}
		if len(names) > 1 {
			authRef.Namespace = names[0]
			authRef.Name = names[1]
		} else {
			authRef.Namespace = obj.GetNamespace()
			authRef.Name = names[0]
		}
	} else {
		// if no authRef configured we try and grab the 'default' from the
		// Operator's current namespace.
		authRef = types.NamespacedName{
			Namespace: OperatorNamespace,
			Name:      consts.NameDefault,
		}
	}
	target = types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
	return authRef, target, nil
}

// According to the spec for secretsv1beta1.VaultAuth, Spec.AllowedNamespaces behaves as follows:
// AllowedNamespaces:
//
//	unset - disallow all except the OperatorNamespace and the AuthMethod's ns, default behavior.
//	[]{"*"} - with length of 1, all namespaces are allowed
//	[]{"a","b"} - explicitly namespaces a, b are allowed
func AllowedNamespace(auth *secretsv1beta1.VaultAuth, name types.NamespacedName) bool {
	// Allow if target ns is the same as auth
	if name.Namespace == auth.ObjectMeta.Namespace {
		return true
	}
	// Default Auth Method
	if auth.ObjectMeta.Name == consts.NameDefault && auth.ObjectMeta.Namespace == OperatorNamespace {
		return true
	}
	// Disallow by default
	if auth.Spec.AllowedNamespaces == nil || len(auth.Spec.AllowedNamespaces) == 0 {
		return false
	}
	// Wildcard
	if len(auth.Spec.AllowedNamespaces) == 1 && auth.Spec.AllowedNamespaces[0] == "*" {
		return true
	}
	// Explicitly set.
	for _, ns := range auth.Spec.AllowedNamespaces {
		if name.Namespace == ns {
			return true
		}
	}
	return false
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
	if !AllowedNamespace(authObj, target) {
		return nil, types.NamespacedName{}, fmt.Errorf(fmt.Sprintf("target namespace is not allowed for this auth method, targetns: %v, authMethod:%s", target.Namespace, authRef.Name))
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
	var vaultConnectionRefName string
	vcrNames := strings.Split(a.Spec.VaultConnectionRef, "/")
	if len(vcrNames) == 1 {
		vaultConnectionRefNamespace = a.Namespace
		vaultConnectionRefName = vcrNames[0]
	} else {
		vaultConnectionRefNamespace = vcrNames[0]
		vaultConnectionRefName = vcrNames[1]
	}

	return types.NamespacedName{
		Namespace: vaultConnectionRefNamespace,
		Name:      vaultConnectionRefName,
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

// SyncableSecretMetaData provides common data structure that extracts the bits pertinent
// when handling any of the sync-able secret custom resource types.
//
// See NewSyncableSecretMetaData for the supported object types.
type SyncableSecretMetaData struct {
	// APIVersion of the syncable-secret object. Maps to obj.APIVersion.
	APIVersion string
	// Kind of the syncable-secret object. Maps to obj.Kind.
	Kind string
	// Destination of the syncable-secret object. Maps to obj.Spec.Destination.
	Destination *secretsv1beta1.Destination
	AuthRef     string
}

// NewSyncableSecretMetaData returns SyncableSecretMetaData if obj is a supported type.
// An error will be returned of obj is not a supported type.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func NewSyncableSecretMetaData(obj ctrlclient.Object) (*SyncableSecretMetaData, error) {
	switch t := obj.(type) {
	case *secretsv1beta1.VaultDynamicSecret:
		return &SyncableSecretMetaData{
			Destination: &t.Spec.Destination,
			APIVersion:  t.APIVersion,
			Kind:        t.Kind,
			AuthRef:     t.Spec.VaultAuthRef,
		}, nil
	case *secretsv1beta1.VaultStaticSecret:
		return &SyncableSecretMetaData{
			Destination: &t.Spec.Destination,
			APIVersion:  t.APIVersion,
			Kind:        t.Kind,
			AuthRef:     t.Spec.VaultAuthRef,
		}, nil
	case *secretsv1beta1.VaultPKISecret:
		return &SyncableSecretMetaData{
			Destination: &t.Spec.Destination,
			APIVersion:  t.APIVersion,
			Kind:        t.Kind,
			AuthRef:     t.Spec.VaultAuthRef,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", t)
	}
}
