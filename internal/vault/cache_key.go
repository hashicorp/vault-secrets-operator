// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/vault/credentials"
)

var (
	errorKeyLengthExceeded = errors.New("cache-key length exceeded")
	errorDuplicateUID      = errors.New("duplicate UID")
	errorInvalidUIDLength  = errors.New("invalid UID length")
	cacheKeyRe             = regexp.MustCompile(fmt.Sprintf(
		`(%s)-[[:xdigit:]]{22}`,
		strings.Join(credentials.ProviderMethodsSupported, "|")))
	cloneKeyRe = regexp.MustCompile(fmt.Sprintf(`^%s-.+$`, cacheKeyRe))
)

// ClientCacheKey is a type that holds the unique value of an entity in a ClientCache.
// Being a type captures intent, even if only being an alias to string.
type ClientCacheKey string

func (k ClientCacheKey) String() string {
	return string(k)
}

func (k ClientCacheKey) IsClone() bool {
	return cloneKeyRe.MatchString(k.String())
}

// ComputeClientCacheKeyFromClient for use in a ClientCache. It is derived from the configuration the Client.
// If the Client is not properly initialized, an error will be returned.
//
// See computeClientCacheKey for more details on how the client cache is derived
func ComputeClientCacheKeyFromClient(c Client) (ClientCacheKey, error) {
	return computeClientCacheKey(c.GetVaultAuthObj(), c.GetVaultConnectionObj(), c.GetCredentialProvider().GetUID())
}

// ComputeClientCacheKeyFromObj for use in a ClientCache. It is derived from the configuration of obj.
// If the obj is not of a supported type or is not properly configured, an error will be returned.
// This operation calls out to the Kubernetes API multiple times.
//
// See computeClientCacheKey for more details on how the client cache is derived.
func ComputeClientCacheKeyFromObj(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (ClientCacheKey, error) {
	authObj, err := common.GetVaultAuthNamespaced(ctx, client, obj)
	if err != nil {
		return "", err
	}

	connName, err := common.GetConnectionNamespacedName(authObj)
	if err != nil {
		return "", err
	}

	connObj, err := common.GetVaultConnection(ctx, client, connName)
	if err != nil {
		return "", err
	}

	provider, err := credentials.NewCredentialProvider(ctx, client, authObj, obj.GetNamespace())
	if err != nil {
		return "", err
	}

	return computeClientCacheKey(authObj, connObj, provider.GetUID())
}

// computeClientCacheKey for use in a ClientCache. It is derived by combining instances of
// VaultAuth, VaultConnection, and a CredentialProvider UID.
// All of these elements are summed together into a SHA256 checksum,
// and prefixed with the VaultAuth method. The chances of a collision are extremely remote,
// since the inputs into the hash should always be unique. For example, we use the UUID
// from three different sources as inputs.
//
// The resulting key will resemble something like: kubernetes-2a8108711ae49ac0faa724, where the prefix
// is the VaultAuth.Spec.Method, and the remainder is the concatenation of the
// first 7 and last 4 bytes of the computed SHA256 check-sum in hex.
//
// The key is included in the name of the corev1.Secrets created by the ClientCacheStorage,
// so its important that any name that includes the cache-key does not exceed the max length
// allowed for Kubernetes resources, which is 63 characters.
//
// If the computed cache-key exceeds 63 characters, the limit imposed for Kubernetes resource names,
// or if any of the inputs do not coform in any way, and error will be returned.
func computeClientCacheKey(authObj *secretsv1beta1.VaultAuth, connObj *secretsv1beta1.VaultConnection, providerUID types.UID) (ClientCacheKey, error) {
	var errs error
	method := authObj.Spec.Method
	if method == "" {
		errs = errors.Join(errs, fmt.Errorf("auth method is empty"))
	}

	// only used for duplicate UID detection, all values are ignored
	seen := make(map[types.UID]int)
	requireUIDLen := 36
	validateUID := func(name string, uid types.UID) {
		if len(uid) != requireUIDLen {
			errs = errors.Join(errs, fmt.Errorf("%w %d, must be %d", errorInvalidUIDLength, len(uid), requireUIDLen))
		}
		if _, ok := seen[uid]; ok {
			errs = errors.Join(errs, fmt.Errorf("%w %s", errorDuplicateUID, uid))
		}
		seen[uid] = 1
	}

	validateUID("authUID", authObj.GetUID())
	validateUID("connUID", connObj.GetUID())
	validateUID("providerUID", providerUID)

	if errs != nil {
		return "", errs
	}

	input := fmt.Sprintf("%s-%d.%s-%d.%s",
		authObj.GetUID(), authObj.GetGeneration(),
		connObj.GetUID(), connObj.GetGeneration(), providerUID)

	sum := sha256.Sum256([]byte(input))
	key := strings.ToLower(method + "-" + fmt.Sprintf("%x%x", sum[0:7], sum[len(sum)-4:]))
	if len(key) > 63 {
		return "", errorKeyLengthExceeded
	}

	return ClientCacheKey(key), nil
}

// ClientCacheKeyClone returns a ClientCacheKey that contains the Vault namespace as its suffix.
// The clone key is meant to differentiate a "parent" cache key from its clones.
func ClientCacheKeyClone(key ClientCacheKey, namespace string) (ClientCacheKey, error) {
	if namespace == "" {
		return "", errors.New("namespace cannot be empty")
	}

	if key.IsClone() {
		return "", errors.New("parent key cannot be a clone")
	}

	return ClientCacheKey(fmt.Sprintf("%s-%s", key, namespace)), nil
}
