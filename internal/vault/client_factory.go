// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"sync"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

type ClientFactory interface {
	GetClient(context.Context, ctrlclient.Client, ctrlclient.Object) (Client, error)
	RemoveObject(ctrlclient.Object) bool
}

var _ ClientFactory = (*cachingClientFactory)(nil)

type cachingClientFactory struct {
	clientCache        ClientCache
	objKeyCache        ObjectKeyCache
	clientCacheStorage ClientCacheStorage
	recorder           record.EventRecorder
	mu                 sync.Mutex
}

func (m *cachingClientFactory) RemoveObject(obj ctrlclient.Object) bool {
	return m.objKeyCache.Remove(ctrlclient.ObjectKeyFromObject(obj))
}

// GetClient is meant to be called for all resources that require access to Vault.
// It will attempt to fetch a Client from the in-memory cache for the provided Object.
// On a cache miss, an attempt at restoration from storage will be made, if a restoration attempt fails,
// a new Client will be instantiated, and an attempt to login into Vault will be made.
// Upon successful restoration/instantiation/login, the Client will be cached for calls.
func (m *cachingClientFactory) GetClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object) (Client, error) {
	// TODO: consider locking on cacheKey
	m.mu.Lock()
	defer m.mu.Unlock()

	objKey := ctrlclient.ObjectKeyFromObject(obj)
	cacheKey, inObjKeyCache := m.objKeyCache.Get(objKey)
	if !inObjKeyCache {
		ck, err := GetClientCacheKeyFromObj(ctx, client, obj)
		if err != nil {
			m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonUnrecoverable,
				"Failed to get cacheKey from obj, err=%s", err)
			return nil, err
		}
		cacheKey = ck
	}

	vc, ok := m.clientCache.Get(cacheKey)
	if !ok {
		// try and restore from storage cache
		ccObj := &secretsv1alpha1.VaultClientCache{}
		if err := client.Get(ctx, clientCacheObjectKey(cacheKey), ccObj); err == nil {
			if c, err := m.restoreClient(ctx, client, obj, ccObj); err == nil {
				vc = c
			}
		}
	}

	if vc != nil {
		if err := m.renewIfNeeded(ctx, obj, vc, 3); err == nil {
			cacheKey, err := m.cacheClient(ctx, client, vc)
			if err != nil {
				return nil, err
			}

			m.objKeyCache.Add(objKey, cacheKey)
			return vc, nil
		}
	}

	// finally create a new client and cache it
	vc, err := NewClientWithLogin(ctx, client, obj)
	if err != nil {
		return nil, err
	}

	cacheKey, err = m.cacheClient(ctx, client, vc)
	if err != nil {
		return nil, err
	}

	m.objKeyCache.Add(objKey, cacheKey)

	return vc, nil
}

func (m *cachingClientFactory) renewIfNeeded(ctx context.Context, obj ctrlclient.Object, c Client, expiry int64) error {
	if ok, err := c.CheckExpiry(expiry); !ok && err == nil {
		return nil
	}

	if err := c.Renew(ctx); err != nil {
		return err
	}

	m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonClientTokenRenewal,
		"Successfully renewed the client token")
	return nil
}

func (m *cachingClientFactory) restoreClient(ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, vccObj *secretsv1alpha1.VaultClientCache) (Client, error) {
	if vccObj.Status.CacheSecretRef == "" {
		return nil, fmt.Errorf("cannot restore, CacheSecrtRef not set")
	}

	req := ClientCacheStorageRestoreRequest{
		Requestor: ctrlclient.ObjectKeyFromObject(vccObj),
		SecretObjKey: types.NamespacedName{
			Namespace: vccObj.Namespace,
			Name:      vccObj.Status.CacheSecretRef,
		},
		CacheKey: vccObj.Spec.CacheKey,
	}

	apiSecret, err := m.clientCacheStorage.Restore(ctx, client, req)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonCacheRestorationFailed,
			"Cache restoration failed, err=%s", err)
		return nil, err
	}

	c, err := NewClient(ctx, client, obj)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client instantiation failed, err=%s", err)
		return nil, err
	}

	if err := c.Restore(ctx, apiSecret); err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client could not be restored, err=%s", err)
		return nil, err
	}

	cacheKey, err := m.cacheClient(ctx, client, c)
	if err != nil {
		m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientInstantiation,
			"Vault Client could not be cached, err=%s", err)
		return nil, err
	}

	m.recorder.Eventf(obj, v1.EventTypeNormal, consts.ReasonCacheRestorationSucceeded,
		"Successfully restored Vault Client from storage cache, cacheKey=%s", cacheKey)
	return c, nil
}

// CacheClient in the global in-memory cache, and create a corresponding
// VaultClientCache resource to handle Client Token renewal, and in-memory cache management.
func (m *cachingClientFactory) cacheClient(ctx context.Context, client ctrlclient.Client, c Client) (string, error) {
	var err error
	cacheKey, err := c.GetCacheKey()
	if err != nil {
		return "", err
	}

	authObj, err := c.GetVaultAuthObj()
	if err != nil {
		return "", err
	}

	connObj, err := c.GetVaultConnectionObj()
	if err != nil {
		return "", err
	}

	providerUID, err := c.GetProviderID()
	if err != nil {
		return "", err
	}

	if _, err := m.clientCache.Add(c); err != nil {
		return "", err
	}

	objKey := clientCacheObjectKey(cacheKey)
	obj := &secretsv1alpha1.VaultClientCache{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      objKey.Name,
			Namespace: objKey.Namespace,
			// These labels are required for cache eviction done by either the VaultAuth
			// or VaultConnection controllers. They are used to find any referent VaultClientCache resources.
			// Those controllers will evict/delete a referent VaultClientCache on update or delete.
			Labels: map[string]string{
				"vaultAuthRef":                authObj.Name,
				"vaultAuthRefNamespace":       authObj.Namespace,
				"vaultConnectionRef":          connObj.Name,
				"vaultConnectionRefNamespace": connObj.Namespace,
			},
		},
		Spec: secretsv1alpha1.VaultClientCacheSpec{
			CacheKey:                  cacheKey,
			VaultAuthName:             authObj.Name,
			VaultAuthNamespace:        authObj.Namespace,
			VaultAuthMethod:           authObj.Spec.Method,
			VaultAuthUID:              authObj.UID,
			VaultAuthGeneration:       authObj.Generation,
			VaultConnectionUID:        connObj.UID,
			VaultConnectionGeneration: connObj.Generation,
			CredentialProviderUID:     providerUID,
			VaultTransitRef:           authObj.Spec.VaultTransitRef,
		},
	}

	action := "created"
	if err := client.Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			action = "patched"
			cur := &secretsv1alpha1.VaultClientCache{}
			if err := client.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), cur); err != nil {
				return "", err
			}

			patch := ctrlclient.MergeFrom(cur.DeepCopy())
			cur.Spec = obj.Spec
			cur.ObjectMeta.OwnerReferences = obj.ObjectMeta.OwnerReferences
			cur.ObjectMeta.Labels = obj.ObjectMeta.Labels
			if err := client.Patch(ctx, cur, patch); err != nil {
				m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientCacheCreation,
					"Patching failed, err=%s", err)
				return "", err
			}
		} else {
			m.recorder.Eventf(obj, v1.EventTypeWarning, consts.ReasonVaultClientCacheCreation,
				"Creating failed, err=%s", err)
			return "", err
		}
	}

	m.recorder.Eventf(obj, v1.EventTypeNormal, consts.ReasonVaultClientCacheCreation,
		"Successfully %s", action)
	// clientSize := reflect.TypeOf(c).Size()

	return cacheKey, nil
}

func NewCachingClientFactory(clientCache ClientCache, objKeyCache ObjectKeyCache, cacheStorage ClientCacheStorage, recorder record.EventRecorder) (ClientFactory, error) {
	return &cachingClientFactory{
		clientCache:        clientCache,
		objKeyCache:        objKeyCache,
		clientCacheStorage: cacheStorage,
		recorder:           recorder,
	}, nil
}

func clientCacheObjectKey(cacheKey string) ctrlclient.ObjectKey {
	return ctrlclient.ObjectKey{
		Namespace: common.OperatorNamespace,
		Name:      "vso-client-cache-" + cacheKey,
	}
}
