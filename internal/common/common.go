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
	vaultcredsconsts "github.com/hashicorp/vault-secrets-operator/internal/credentials/vault/consts"
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
	RefKind   string
	AllowedNS []string
}

func (n *NamespaceNotAllowedError) Error() string {
	refKind := n.RefKind
	if refKind == "" {
		refKind = "unknown"
	}
	return fmt.Sprintf(
		"target namespace %q is not allowed by kind=%s obj=%s, allowedNamespaces=%v",
		n.TargetNS, refKind, n.ObjRef, n.AllowedNS)
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

	authRef, err := ParseResourceRef(m.AuthRef, obj.GetNamespace())
	if err != nil {
		return types.NamespacedName{}, err
	}
	return authRef, nil
}

// ParseResourceRef parses an input string and returns a types.NamespacedName
// with appropriate namespace and name set or otherwise overridden as default.
func ParseResourceRef(refName, defaultNamespace string) (types.NamespacedName, error) {
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
			RefKind:  "VaultAuth",
		}
	}

	if authObj.Spec.VaultAuthGlobalRef != "" {
		authObj, _, err = MergeInVaultAuthGlobal(ctx, c, authObj)
		if err != nil {
			return nil, err
		}
	}
	return authObj, nil
}

// MergeInVaultAuthGlobal merges the VaultAuthGlobal object into the VaultAuth
// object. The VaultAuthGlobal object is referenced by the VaultAuth object. The
// VaultAuthGlobal object is fetched and merged into the VaultAuth object. In the
// case where no reference is specified in the VaultAuth object, the VaultAuth
// object is returned as is.
func MergeInVaultAuthGlobal(ctx context.Context, c ctrlclient.Client, o *secretsv1beta1.VaultAuth) (*secretsv1beta1.VaultAuth, *secretsv1beta1.VaultAuthGlobal, error) {
	if o.Spec.VaultAuthGlobalRef == "" {
		return o, nil, nil
	}

	cObj := o.DeepCopy()
	authGlobalRef, err := ParseResourceRef(cObj.Spec.VaultAuthGlobalRef, cObj.GetNamespace())
	if err != nil {
		return nil, nil, err
	}

	var gObj secretsv1beta1.VaultAuthGlobal
	if err := c.Get(ctx, authGlobalRef, &gObj); err != nil {
		return nil, nil, fmt.Errorf("failed getting %s, err=%w", authGlobalRef, err)
	}

	if !isAllowedNamespace(&gObj, cObj.GetNamespace(), gObj.Spec.AllowedNamespaces...) {
		return nil, nil, &NamespaceNotAllowedError{
			TargetNS: cObj.GetNamespace(),
			ObjRef:   authGlobalRef,
			RefKind:  "VaultAuthGlobal",
		}
	}

	// authMethod is the method to be used in the VaultAuth object. If the method is
	// not set in the VaultAuth object, the default method from the VaultAuthGlobal
	// object is used.
	if cObj.Spec.Method == "" {
		if gObj.Spec.DefaultAuthMethod == "" {
			return nil, nil, fmt.Errorf(
				"no auth method set in VaultAuth %s and no default method set in VaultAuthGlobal %s",
				client.ObjectKeyFromObject(cObj), authGlobalRef)
		}
		cObj.Spec.Method = gObj.Spec.DefaultAuthMethod
	}

	var globalAuthMount string
	var globalAuthNamespace string
	var globalAuthParams map[string]string
	var globalAuthHeaders map[string]string
	switch cObj.Spec.Method {
	case vaultcredsconsts.ProviderMethodKubernetes:
		globalAuthMethod := gObj.Spec.Kubernetes
		mergeTargetAuthMethod := cObj.Spec.Kubernetes
		if mergeTargetAuthMethod == nil && globalAuthMethod == nil {
			return nil, nil, fmt.Errorf("global auth method %s is not configured "+
				"in VaultAuthGlobal %s", cObj.Spec.Method, authGlobalRef)
		}

		if globalAuthMethod != nil {
			srcAuthMethod := globalAuthMethod.VaultAuthConfigKubernetes.DeepCopy()
			if mergeTargetAuthMethod == nil {
				cObj.Spec.Kubernetes = srcAuthMethod
			} else {
				merged, err := mergeTargetAuthMethod.Merge(srcAuthMethod)
				if err != nil {
					return nil, nil, err
				}
				cObj.Spec.Kubernetes = merged
			}
			if err := cObj.Spec.Kubernetes.Validate(); err != nil {
				return nil, nil, err
			}
			globalAuthMount = globalAuthMethod.Mount
			globalAuthNamespace = globalAuthMethod.Namespace
			globalAuthParams = globalAuthMethod.Params
			globalAuthHeaders = globalAuthMethod.Headers
		}
	case vaultcredsconsts.ProviderMethodJWT:
		globalAuthMethod := gObj.Spec.JWT
		mergeTargetAuthMethod := cObj.Spec.JWT
		if mergeTargetAuthMethod == nil && globalAuthMethod == nil {
			return nil, nil, fmt.Errorf("global auth method %s is not configured "+
				"in VaultAuthGlobal %s", cObj.Spec.Method, authGlobalRef)
		}

		if globalAuthMethod != nil {
			srcAuthMethod := globalAuthMethod.VaultAuthConfigJWT.DeepCopy()
			if mergeTargetAuthMethod == nil {
				cObj.Spec.JWT = srcAuthMethod
			} else {
				merged, err := mergeTargetAuthMethod.Merge(srcAuthMethod)
				if err != nil {
					return nil, nil, err
				}
				cObj.Spec.JWT = merged
			}
			if err := cObj.Spec.JWT.Validate(); err != nil {
				return nil, nil, err
			}
			globalAuthMount = globalAuthMethod.Mount
			globalAuthNamespace = globalAuthMethod.Namespace
			globalAuthParams = globalAuthMethod.Params
			globalAuthHeaders = globalAuthMethod.Headers
		}
	case vaultcredsconsts.ProviderMethodAppRole:
		globalAuthMethod := gObj.Spec.AppRole
		mergeTargetAuthMethod := cObj.Spec.AppRole
		if mergeTargetAuthMethod == nil && globalAuthMethod == nil {
			return nil, nil, fmt.Errorf("global auth method %s is not configured "+
				"in VaultAuthGlobal %s", cObj.Spec.Method, authGlobalRef)
		}

		if globalAuthMethod != nil {
			srcAuthMethod := globalAuthMethod.VaultAuthConfigAppRole.DeepCopy()
			if mergeTargetAuthMethod == nil {
				cObj.Spec.AppRole = srcAuthMethod
			} else {
				merged, err := mergeTargetAuthMethod.Merge(srcAuthMethod)
				if err != nil {
					return nil, nil, err
				}
				cObj.Spec.AppRole = merged
			}
			if err := cObj.Spec.AppRole.Validate(); err != nil {
				return nil, nil, err
			}
			globalAuthMount = globalAuthMethod.Mount
			globalAuthNamespace = globalAuthMethod.Namespace
			globalAuthParams = globalAuthMethod.Params
			globalAuthHeaders = globalAuthMethod.Headers
		}
	case vaultcredsconsts.ProviderMethodAWS:
		globalAuthMethod := gObj.Spec.AWS
		mergeTargetAuthMethod := cObj.Spec.AWS
		if mergeTargetAuthMethod == nil && globalAuthMethod == nil {
			return nil, nil, fmt.Errorf("global auth method %s is not configured "+
				"in VaultAuthGlobal %s", cObj.Spec.Method, authGlobalRef)
		}

		if globalAuthMethod != nil {
			srcAuthMethod := globalAuthMethod.VaultAuthConfigAWS.DeepCopy()
			if mergeTargetAuthMethod == nil {
				cObj.Spec.AWS = srcAuthMethod
			} else {
				merged, err := mergeTargetAuthMethod.Merge(srcAuthMethod)
				if err != nil {
					return nil, nil, err
				}
				cObj.Spec.AWS = merged
			}
			if err := cObj.Spec.AWS.Validate(); err != nil {
				return nil, nil, err
			}
			globalAuthMount = globalAuthMethod.Mount
			globalAuthNamespace = globalAuthMethod.Namespace
			globalAuthParams = globalAuthMethod.Params
			globalAuthHeaders = globalAuthMethod.Headers
		}
	case vaultcredsconsts.ProviderMethodGCP:
		globalAuthMethod := gObj.Spec.GCP
		mergeTargetAuthMethod := cObj.Spec.GCP
		if mergeTargetAuthMethod == nil && globalAuthMethod == nil {
			return nil, nil, fmt.Errorf("global auth method %s is not configured "+
				"in VaultAuthGlobal %s", cObj.Spec.Method, authGlobalRef)
		}

		if globalAuthMethod != nil {
			srcAuthMethod := globalAuthMethod.VaultAuthConfigGCP.DeepCopy()
			if mergeTargetAuthMethod == nil {
				cObj.Spec.GCP = srcAuthMethod
			} else {
				merged, err := mergeTargetAuthMethod.Merge(srcAuthMethod)
				if err != nil {
					return nil, nil, err
				}
				cObj.Spec.GCP = merged
			}
			if err := cObj.Spec.GCP.Validate(); err != nil {
				return nil, nil, err
			}
			globalAuthMount = globalAuthMethod.Mount
			globalAuthNamespace = globalAuthMethod.Namespace
			globalAuthParams = globalAuthMethod.Params
			globalAuthHeaders = globalAuthMethod.Headers
		}
	default:
		return nil, nil, fmt.Errorf(
			"unsupported auth method %q for global auth merge",
			cObj.Spec.Method,
		)
	}

	cObj.Spec.Mount = firstNonZeroLen(strLenFunc,
		cObj.Spec.Mount, globalAuthMount, gObj.Spec.DefaultMount)
	if cObj.Spec.Mount == "" {
		return nil, nil, fmt.Errorf(
			"mount is not set in VaultAuth %s after merge with %s",
			client.ObjectKeyFromObject(cObj), authGlobalRef,
		)
	}

	cObj.Spec.Namespace = firstNonZeroLen(strLenFunc,
		cObj.Spec.Namespace, globalAuthNamespace, gObj.Spec.DefaultVaultNamespace)
	cObj.Spec.Headers = firstNonZeroLen(mapLenFunc[string, string],
		cObj.Spec.Headers, globalAuthHeaders, gObj.Spec.DefaultHeaders)
	cObj.Spec.Params = firstNonZeroLen(mapLenFunc[string, string],
		cObj.Spec.Params, globalAuthParams, gObj.Spec.DefaultParams)

	cObj.Spec.VaultConnectionRef = firstNonZeroLen(strLenFunc,
		cObj.Spec.VaultConnectionRef, gObj.Spec.VaultConnectionRef)

	return cObj, &gObj, nil
}

func strLenFunc(s string) int {
	return len(s)
}

func mapLenFunc[K comparable, V any](m map[K]V) int {
	return len(m)
}

func firstNonZeroLen[V any](lenFunc func(V) int, m ...V) (ret V) {
	for _, v := range m {
		if lenFunc(v) > 0 {
			ret = v
			break
		}
	}
	return
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
			RefKind:  "HCPAuth",
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

func GetSecretTransformation(ctx context.Context, c client.Client, key types.NamespacedName) (*secretsv1beta1.SecretTransformation, error) {
	var obj secretsv1beta1.SecretTransformation
	if err := c.Get(ctx, key, &obj); err != nil {
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
	connRef, err := ParseResourceRef(a.Spec.VaultConnectionRef, a.GetNamespace())
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
	// Name
	Name string
	// Namespace
	Namespace string
	// Destination of the syncable-secret object. Maps to obj.Spec.Destination.
	Destination *secretsv1beta1.Destination
	AuthRef     string
}

// NewSyncableSecretMetaData returns SyncableSecretMetaData if obj is a supported type.
// An error will be returned of obj is not a supported type.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret. VaultPKISecret
func NewSyncableSecretMetaData(obj ctrlclient.Object) (*SyncableSecretMetaData, error) {
	meta := &SyncableSecretMetaData{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}

	switch t := obj.(type) {
	case *secretsv1beta1.VaultDynamicSecret:
		meta.Destination = t.Spec.Destination.DeepCopy()
		meta.APIVersion = t.APIVersion
		meta.Kind = t.Kind
		meta.AuthRef = t.Spec.VaultAuthRef
	case *secretsv1beta1.VaultStaticSecret:
		meta.Destination = t.Spec.Destination.DeepCopy()
		meta.APIVersion = t.APIVersion
		meta.Kind = t.Kind
		meta.AuthRef = t.Spec.VaultAuthRef
	case *secretsv1beta1.VaultPKISecret:
		meta.Destination = t.Spec.Destination.DeepCopy()
		meta.APIVersion = t.APIVersion
		meta.Kind = t.Kind
		meta.AuthRef = t.Spec.VaultAuthRef
	case *secretsv1beta1.HCPVaultSecretsApp:
		meta.Destination = t.Spec.Destination.DeepCopy()
		meta.APIVersion = t.APIVersion
		meta.Kind = t.Kind
		meta.AuthRef = t.Spec.HCPAuthRef
	default:
		return nil, fmt.Errorf("unsupported type %T", t)
	}

	return meta, nil
}
