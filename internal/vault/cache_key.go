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

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

var cacheKeyRe = regexp.MustCompile(fmt.Sprintf(
	`((?:%s)-[a-f0-9]{7})`, strings.Join(providerMethodsSupported, "|")),
)

func GenCacheClientKeyFromObjs(authObj *secretsv1alpha1.VaultAuth, connObj *secretsv1alpha1.VaultConnection, providerUID types.UID) (string, error) {
	return genCacheClientKey(authObj.Spec.Method,
		authObj.GetUID(), authObj.GetGeneration(),
		connObj.GetUID(), connObj.GetGeneration(), providerUID,
	)
}

func genCacheClientKey(method string, authUID types.UID, authGen int64, connUID types.UID, connGen int64, providerUID types.UID) (string, error) {
	var err error
	if method == "" {
		err = errors.Join(err, fmt.Errorf("auth method is empty"))
	}

	checkLen := func(name string, uid types.UID) {
		if len(uid) != 36 {
			err = errors.Join(err, fmt.Errorf("invalid length for %s, must be 36", name))
		}
	}

	checkLen("authUID", authUID)
	checkLen("connUID", connUID)
	checkLen("providerUID", providerUID)

	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s-%d.%s-%d.%s", authUID, authGen, connUID, connGen, providerUID)

	s := sha256.Sum256([]byte(key))
	return method + "-" + fmt.Sprintf("%x", s)[0:7], nil
}

func GetClientCacheKeyFromObj(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (string, error) {
	authObj, _, err := common.GetVaultAuthAndTarget(ctx, client, obj)
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

	provider, err := NewCredentialProvider(ctx, client, obj, authObj.Spec.Method)
	if err != nil {
		return "", err
	}

	return GenCacheClientKeyFromObjs(authObj, connObj, provider.GetUID())
}

func GetCacheKeyFromObjName(obj ctrlclient.Object) (string, error) {
	match := vccNameRe.FindStringSubmatch(obj.GetName())
	if len(match) != 2 {
		return "", fmt.Errorf("object's name %q is invalid", obj.GetName())
	}
	return match[1], nil
}
