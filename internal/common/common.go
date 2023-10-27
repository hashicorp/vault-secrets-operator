// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	InvalidObjectKeyError                      = fmt.Errorf("invalid objectKey")
	InvalidObjectKeyErrorEmptyName             = fmt.Errorf("%w, empty name", InvalidObjectKeyError)
	InvalidObjectKeyErrorEmptyNamespace        = fmt.Errorf("%w, empty namespace", InvalidObjectKeyError)
	defaultMaxRetries                   uint64 = 60
	defaultRetryDuration                       = time.Millisecond * 500
)

type NamespaceNotAllowedError struct {
	TargetNS  string
	ObjRef    types.NamespacedName
	AllowedNS []string
}

func (n *NamespaceNotAllowedError) Error() string {
	return fmt.Sprintf(
		"target namespace %q is not allowed by authRef %s, allowed=%v",
		n.TargetNS, n.ObjRef, n.AllowedNS)
}

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

func getAuthRefNamespacedName(obj client.Object) (types.NamespacedName, error) {
	m, err := NewSyncableSecretMetaData(obj)
	if err != nil {
		return types.NamespacedName{}, err
	}

	authRef, err := parseResourceRef(m.AuthRef, obj.GetNamespace())
	if err != nil {
		return types.NamespacedName{}, err
	}
	return authRef, nil
}

// parseResourceRef parses an input string and returns a types.NamespacedName
// with appropriate namespace and name set or otherwise overridden as default.
func parseResourceRef(refName, defaultNamespace string) (types.NamespacedName, error) {
	var ref types.NamespacedName
	if refName != "" {
		names := strings.Split(refName, "/")
		if len(names) > 2 {
			return types.NamespacedName{}, fmt.Errorf("invalid name: %s", refName)
		}
		if len(names) > 1 {
			ref.Namespace = names[0]
			ref.Name = names[1]
		} else {
			ref.Namespace = defaultNamespace
			ref.Name = names[0]
		}
	} else {
		// if no authRef configured we use the 'default' from the Operator's namespace.
		ref.Namespace = OperatorNamespace
		ref.Name = consts.NameDefault
	}
	return ref, nil
}

// isAllowedNamespace computes whether a targetNamespace is allowed based on the AllowedNamespaces
// field of the VaultAuth or HCPAuth objects.
//
// isAllowedNamespace behaves as follows:
//
//	unset - disallow all except the OperatorNamespace and the AuthMethod's ns, default behavior.
//	[]{"*"} - with length of 1, all namespaces are allowed
//	[]{"a","b"} - explicitly namespaces a, b are allowed
func isAllowedNamespace(obj ctrlclient.Object, targetNamespace string, allowed ...string) bool {
	// Allow if target ns is the same as auth
	if targetNamespace == obj.GetNamespace() {
		return true
	}
	// Default Auth Method
	if obj.GetName() == consts.NameDefault && obj.GetNamespace() == OperatorNamespace {
		return true
	}

	lenAllowed := len(allowed)
	// Disallow by default
	if lenAllowed == 0 {
		return false
	}
	// Wildcard
	if lenAllowed == 1 && allowed[0] == "*" {
		return true
	}
	// Explicitly set.
	for _, ns := range allowed {
		if targetNamespace == ns {
			return true
		}
	}
	return false
}

func GetVaultAuthNamespaced(ctx context.Context, c client.Client, obj client.Object) (*secretsv1beta1.VaultAuth, error) {
	authRef, err := getAuthRefNamespacedName(obj)
	if err != nil {
		return nil, err
	}

	authObj, err := GetVaultAuthWithRetry(ctx, c, authRef, defaultRetryDuration, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	if !isAllowedNamespace(authObj, obj.GetNamespace(), authObj.Spec.AllowedNamespaces...) {
		return nil, &NamespaceNotAllowedError{
			TargetNS: obj.GetNamespace(),
			ObjRef:   authRef,
		}
	}
	return authObj, nil
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

// GetHCPAuthForObj returns the corresponding secretsv1beta1.HCPAuth for obj.
// Supported client.Object: secretsv1beta1.HCPVaultSecretsApp
func GetHCPAuthForObj(ctx context.Context, c client.Client, obj client.Object) (*secretsv1beta1.HCPAuth, error) {
	authRef, err := getAuthRefNamespacedName(obj)
	if err != nil {
		return nil, err
	}

	authObj, err := GetHCPAuthWithRetry(ctx, c, authRef, defaultRetryDuration, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	if !isAllowedNamespace(authObj, obj.GetNamespace(), authObj.Spec.AllowedNamespaces...) {
		return nil, &NamespaceNotAllowedError{
			TargetNS: obj.GetNamespace(),
			ObjRef:   authRef,
		}
	}

	return authObj, nil
}

func GetHCPAuthWithRetry(ctx context.Context, c client.Client, key types.NamespacedName,
	delay time.Duration, max uint64,
) (*secretsv1beta1.HCPAuth, error) {
	var obj secretsv1beta1.HCPAuth
	if err := getWithRetry(ctx, c, key, &obj, delay, max); err != nil {
		return nil, err
	}

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
	if a.Spec.VaultConnectionRef == "" && OperatorNamespace == "" {
		return types.NamespacedName{}, fmt.Errorf("operator's default namespace is not set, this is a bug")
	}
	connRef, err := parseResourceRef(a.Spec.VaultConnectionRef, a.GetNamespace())
	if err != nil {
		return types.NamespacedName{}, err
	}
	return connRef, nil
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
	case *secretsv1beta1.HCPVaultSecretsApp:
		return &SyncableSecretMetaData{
			Destination: &t.Spec.Destination,
			APIVersion:  t.APIVersion,
			Kind:        t.Kind,
			AuthRef:     t.Spec.HCPAuthRef,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", t)
	}
}

// GetKubernetesServiceAccountNamespacedName returns the NamespacedName for the Kubernetes VaultAuth's configured
// serviceAccount.
// If the serviceAccount is empty then defaults Namespace and Name will be returned.
func GetKubernetesServiceAccountNamespacedName(a *secretsv1beta1.VaultAuthConfigKubernetes, providerNamespace string) (types.NamespacedName, error) {
	if a.ServiceAccount == "" && providerNamespace == "" {
		return types.NamespacedName{}, fmt.Errorf("provider's default namespace is not set, this is a bug")
	}
	saRef, err := parseResourceRef(a.ServiceAccount, providerNamespace)
	if err != nil {
		return types.NamespacedName{}, err
	}
	return saRef, nil
}
