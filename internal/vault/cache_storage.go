// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

const (
	labelEncrypted       = "encrypted"
	labelVaultTransitRef = "vaultTransitRef"
	labelCacheKey        = "cacheKey"
	fieldMACMessage      = "messageMAC"
	fieldCachedSecret    = "secret"
)

var (
	InvalidObjectKeyError   = fmt.Errorf("invalid objectKey")
	EncryptionRequiredError = fmt.Errorf("encryption required")
)

type ClientCacheStorageRequest struct {
	OwnerReferences   []metav1.OwnerReference
	TransitObjKey     ctrlclient.ObjectKey
	Client            Client
	EnforceEncryption bool
}

type ClientCacheStoragePruneRequest struct {
	MatchingLabels ctrlclient.MatchingLabels
	Filter         PruneFilterFunc
}

type ClientCacheStorageRestoreRequest struct {
	SecretObjKey ctrlclient.ObjectKey
	CacheKey     ClientCacheKey
}

func (c ClientCacheStorageRequest) Validate() error {
	var err error
	if c.Client == nil {
		err = errors.Join(err, fmt.Errorf("a Client must be set"))
	}

	if c.EnforceEncryption && !c.encryptionConfigured() {
		err = errors.Join(err, fmt.Errorf("a TransitObjKey must be set: %w", EncryptionRequiredError))
	}

	return err
}

func (c ClientCacheStorageRequest) encryptionConfigured() bool {
	return validateObjectKey(c.TransitObjKey) == nil
}

type PruneFilterFunc func(secret corev1.Secret) bool

var _ ClientCacheStorage = (*defaultClientCacheStorage)(nil)

type ClientCacheStorage interface {
	Store(context.Context, ctrlclient.Client, ClientCacheStorageRequest) (*corev1.Secret, error)
	Restore(context.Context, ctrlclient.Client, ClientCacheStorageRestoreRequest) (*api.Secret, error)
	Prune(context.Context, ctrlclient.Client, ClientCacheStoragePruneRequest) (int, error)
}

type defaultClientCacheStorage struct {
	hkdfObjKey        ctrlclient.ObjectKey
	hkdfKey           []byte
	enforceEncryption bool
	mu                sync.RWMutex
}

func (c *defaultClientCacheStorage) getSecret(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	if err := client.Get(ctx, key, s); err != nil {
		return nil, err
	}

	return s, nil
}

func (c *defaultClientCacheStorage) Store(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageRequest) (*corev1.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	logger := log.FromContext(ctx)
	if err := req.Validate(); err != nil {
		return nil, err
	}

	// global encryption policy checks, all requests must require encryption
	logger.Info("ClientCacheStorage.Store()",
		"enforceEncryption", c.enforceEncryption,
		"encryptionConfigured", req.encryptionConfigured())
	if c.enforceEncryption && !req.encryptionConfigured() {
		return nil, fmt.Errorf("request does not support encryption and enforcing enabled: %w", EncryptionRequiredError)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	authObj, err := req.Client.GetVaultAuthObj()
	if err != nil {
		return nil, err
	}

	connObj, err := req.Client.GetVaultConnectionObj()
	if err != nil {
		return nil, err
	}

	cacheKey, err := req.Client.GetCacheKey()
	if err != nil {
		return nil, err
	}

	s := &corev1.Secret{
		// we always store Clients in an Immutable secret as an anti-tampering mitigation.
		Immutable: pointer.Bool(true),
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf(NamePrefixVCC + cacheKey.String()),
			Namespace:       common.OperatorNamespace,
			OwnerReferences: req.OwnerReferences,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "vault-secrets-operator",
				"app.kubernetes.io/managed-by": "vso",
				"app.kubernetes.io/component":  "client-cache-storage",
				// cacheKey is the key used to access a Client from the ClientCache
				labelCacheKey: cacheKey.String(),
				// required for storage cache cleanup performed by the Client's VaultAuth
				// this is done by controllers.VaultAuthReconciler
				"vaultAuthRefUIDGen": fmt.Sprintf("%s_%d", authObj.UID, authObj.Generation),
				// required for storage cache cleanup performed by the Client's VaultConnect
				// this is done by controllers.VaultConnectionReconciler
				"vaultConnectionRefUIDGen": fmt.Sprintf("%s_%d", connObj.UID, connObj.Generation),
			},
		},
	}

	sec, err := req.Client.GetLastResponse()
	if err != nil {
		return nil, err
	}

	var b []byte
	if c.enforceEncryption {
		// needed for restoration
		s.ObjectMeta.Labels[labelEncrypted] = "true"
		s.ObjectMeta.Labels[labelVaultTransitRef] = req.TransitObjKey.Name

		logger.Info("ClientCacheStorage.Store(), calling EncryptWithTransitFromObjKey",
			"enforceEncryption", c.enforceEncryption,
			"encryptionConfigured", req.encryptionConfigured, "transitObjKey", req.TransitObjKey)
		if encBytes, err := EncryptWithTransitFromObjKey(ctx, client, req.TransitObjKey, b); err != nil {
			return nil, err
		} else {
			b = encBytes
		}
	} else {
		b, err = json.Marshal(sec)
		if err != nil {
			return nil, err
		}

	}

	s.Data = map[string][]byte{
		fieldCachedSecret: b,
	}
	message, err := c.message(s.Name, cacheKey.String(), b)
	if err != nil {
		return nil, err
	}

	messageMAC, err := macMessage(c.hkdfKey, message)
	if err != nil {
		return nil, err
	}

	s.Data[fieldMACMessage] = messageMAC
	if err := client.Create(ctx, s); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// since the Secret is immutable we need to always recreate it.
			if err := client.Delete(ctx, s); err != nil {
				return nil, err
			}
			if err := client.Create(ctx, s); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return s, nil
}

func (c *defaultClientCacheStorage) Restore(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageRestoreRequest) (*api.Secret, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s, err := c.getSecret(ctx, client, req.SecretObjKey)
	if err != nil {
		return nil, err
	}

	if err := c.validateSecretMAC(req, s); err != nil {
		return nil, err
	}

	var secret *api.Secret
	if b, ok := s.Data[fieldCachedSecret]; ok {
		transitRef := s.Labels["vaultTransitRef"]
		if transitRef != "" {
			objKey := ctrlclient.ObjectKey{
				Namespace: common.OperatorNamespace,
				Name:      transitRef,
			}

			decBytes, err := DecryptWithTransitFromObjKey(ctx, client, objKey, b)
			if err != nil {
				return nil, err
			}

			b = decBytes
		}

		if err := json.Unmarshal(b, &secret); err != nil {
			return nil, err
		}
	}

	return secret, err
}

func (c *defaultClientCacheStorage) Prune(ctx context.Context, client ctrlclient.Client, req ClientCacheStoragePruneRequest) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	secrets := &corev1.SecretList{}
	if err := client.List(ctx, secrets, req.MatchingLabels); err != nil {
		return 0, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	var count int
	for _, item := range secrets.Items {
		if req.Filter(item) {
			continue
		}

		dcObj := item.DeepCopy()
		if err = client.Delete(ctx, dcObj); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}

			err = errors.Join(err)
			continue
		}
		count++
	}

	return count, err
}

func (c *defaultClientCacheStorage) validateSecretMAC(req ClientCacheStorageRestoreRequest, s *corev1.Secret) error {
	var err error
	b, ok := s.Data[fieldCachedSecret]
	if !ok {
		err = errors.Join(err, fmt.Errorf("entry missing required %q field", fieldCachedSecret))
	}

	messageMAC, ok := s.Data[fieldMACMessage]
	if !ok {
		err = errors.Join(err, fmt.Errorf("entry missing required %q field", fieldCachedSecret))
	}

	if err != nil {
		return err
	}

	message, err := c.message(s.Name, req.CacheKey.String(), b)
	if err != nil {
		return err
	}

	ok, err = validateMAC(message, messageMAC, c.hkdfKey)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("storage entry message MAC is invalid")
	}

	return nil
}

func (c *defaultClientCacheStorage) message(name, cacheKey string, secretData []byte) ([]byte, error) {
	if name == "" || cacheKey == "" {
		return nil, fmt.Errorf("invalid empty name and cacheKey")
	}

	return append([]byte(name+cacheKey), secretData...), nil
}

type ClientCacheStorageConfig struct {
	// EnforceEncryption for persisting Clients i.e. the controller must have VaultTransitRef
	// configured before it will persist the Client to storage. This option requires Persist to be true.
	EnforceEncryption bool
	HKDFObjectKey     ctrlclient.ObjectKey
}

func DefaultClientCacheStorageConfig() *ClientCacheStorageConfig {
	return &ClientCacheStorageConfig{
		EnforceEncryption: false,
		HKDFObjectKey: ctrlclient.ObjectKey{
			Name:      NamePrefixVCC + "storage-hkdf-key",
			Namespace: common.OperatorNamespace,
		},
	}
}

func NewDefaultClientCacheStorage(ctx context.Context, client ctrlclient.Client, config *ClientCacheStorageConfig) (ClientCacheStorage, error) {
	if err := validateObjectKey(config.HKDFObjectKey); err != nil {
		return nil, err
	}

	s, err := CreateHKDFSecret(ctx, client, config.HKDFObjectKey)
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}

	if s == nil {
		s, err = GetHKDFSecret(ctx, client, config.HKDFObjectKey)
		if err != nil {
			return nil, err
		}
	}

	return &defaultClientCacheStorage{
		hkdfObjKey:        config.HKDFObjectKey,
		hkdfKey:           s.Data[hkdfKeyName],
		enforceEncryption: config.EnforceEncryption,
	}, nil
}

func validateObjectKey(key ctrlclient.ObjectKey) error {
	if key.Name == "" || key.Namespace == "" {
		return InvalidObjectKeyError
	}
	return nil
}
