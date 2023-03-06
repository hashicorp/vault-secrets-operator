// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

var (
	errorKeyLengthExceeded = errors.New("cache-key length exceeded")
	errorDuplicateUID      = errors.New("duplicate UID")
	errorInvalidUIDLength  = errors.New("invalid UID length")
)

// ClientCacheKey is a type that holds the unique value of an entity in a ClientCache.
// Being a type captures intent, even if only being an alias to string.
type ClientCacheKey string

func (k ClientCacheKey) String() string {
	return string(k)
}

// ComputeClientCacheKeyFromClient for use in a ClientCache. It is derived from the configuration the Client.
// If the Client is not properly initialized, an error will be returned.
//
// See computeClientCacheKey for more details on how the client cache is derived
func ComputeClientCacheKeyFromClient(c Client) (ClientCacheKey, error) {
	var errs error
	authObj, err := c.GetVaultAuthObj()
	if err != nil {
		errs = errors.Join(err)
	}
	connObj, err := c.GetVaultConnectionObj()
	if err != nil {
		errs = errors.Join(err)
	}

	credentialProvider, err := c.GetCredentialProvider()
	if err != nil {
		errs = errors.Join(err)
	}
	if errs != nil {
		return "", errs
	}

	return computeClientCacheKey(authObj, connObj, credentialProvider.GetUID())
}

// ComputeClientCacheKeyFromObj for use in a ClientCache. It is derived from the configuration of obj.
// If the obj is not of a supported type or is not properly configured, an error will be returned.
// This operation calls out to the Kubernetes API multiple times.
//
// See computeClientCacheKey for more details on how the client cache is derived.
func ComputeClientCacheKeyFromObj(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (ClientCacheKey, error) {
	authObj, target, err := common.GetVaultAuthAndTarget(ctx, client, obj)
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

	provider, err := NewCredentialProvider(ctx, client, authObj, target.Namespace)
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
func computeClientCacheKey(authObj *secretsv1alpha1.VaultAuth, connObj *secretsv1alpha1.VaultConnection, providerUID types.UID) (ClientCacheKey, error) {
	var errs error
	method := authObj.Spec.Method
	if method == "" {
		errs = errors.Join(fmt.Errorf("auth method is empty"))
	}

	// only used for duplicate UID detection, all values are ignored
	seen := make(map[types.UID]int)
	requireUIDLen := 36
	validateUID := func(name string, uid types.UID) {
		if len(uid) != requireUIDLen {
			errs = errors.Join(fmt.Errorf("%w %d, must be %d", errorInvalidUIDLength, len(uid), requireUIDLen))
		}
		if _, ok := seen[uid]; ok {
			errs = errors.Join(fmt.Errorf("%w %s", errorDuplicateUID, uid))
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
	key := method + "-" + fmt.Sprintf("%x%x", sum[0:7], sum[len(sum)-4:])
	if len(key) > 63 {
		return "", errorKeyLengthExceeded
	}

	return ClientCacheKey(key), nil
}
