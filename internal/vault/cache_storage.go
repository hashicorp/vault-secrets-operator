// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

const (
	labelEncrypted       = "encrypted"
	labelVaultTransitRef = "vaultTransitRef"
	labelCacheKey        = "cacheKey"
	fieldMACMessage      = "messageMAC"
	fieldCachedSecret    = "secret"

	labelAuthNamespace        = "auth/namespace"
	labelAuthUID              = "auth/UID"
	labelAuthGeneration       = "auth/generation"
	labelConnectionNamespace  = "connection/namespace"
	labelConnectionUID        = "connection/UID"
	labelConnectionGeneration = "connection/generation"
	labelProviderUID          = "provider/UID"
	labelProviderNamespace    = "provider/namespace"
)

var (
	InvalidObjectKeyError   = fmt.Errorf("invalid objectKey")
	EncryptionRequiredError = fmt.Errorf("encryption required")
)

type ClientCacheStorageStoreRequest struct {
	OwnerReferences     []metav1.OwnerReference
	Client              Client
	EncryptionClient    Client
	EncryptionVaultAuth *secretsv1alpha1.VaultAuth
}

type ClientCacheStoragePruneRequest struct {
	MatchingLabels ctrlclient.MatchingLabels
	Filter         PruneFilterFunc
}

type ClientCacheStorageRestoreRequest struct {
	SecretObjKey        ctrlclient.ObjectKey
	CacheKey            ClientCacheKey
	DecryptionClient    Client
	DecryptionVaultAuth *secretsv1alpha1.VaultAuth
}

type ClientCacheStorageRestoreAllRequest struct {
	DecryptionClient    Client
	DecryptionVaultAuth *secretsv1alpha1.VaultAuth
}

// clientCacheStorageEntry represents a single Vault Client.
// It contains the context needed to restore a Client to its original state.
type clientCacheStorageEntry struct {
	// CacheKey for the Storage entry
	CacheKey ClientCacheKey
	// VaultSecret contains the Vault authentication token
	VaultSecret *api.Secret
	// VaultAuthUID is the unique identifier of the VaultAuth custom resource
	// that was used to create the cached Client.
	VaultAuthUID types.UID
	// VaultAuthNamespace is the k8s namespace of the VaultAuth custom resource
	// that was used to create the cached Client.
	VaultAuthNamespace string
	// VaultAuthGeneration is the generation of the VaultAuth custom resource
	// that was used to create the cached Client.
	VaultAuthGeneration int64
	// VaultConnectionUID is the unique identifier of the VaultConnection custom resource
	// that was used to create the cached Client.
	VaultConnectionUID types.UID
	// VaultConnectionNamespace is the k8s namespace of the VaultConnection custom resource
	// that was used to create the cached Client.
	VaultConnectionNamespace string
	// VaultConnectionGeneration is the generation of the VaultConnection custom resource
	// that was used to create the cached Client.
	VaultConnectionGeneration int64
	// ProviderUID is the unique identifier of the CredentialProvider that
	// was used to create the cached Client.
	ProviderUID types.UID
	// ProviderNamespace is the k8s namespace of the CredentialProvider that
	// was used to create the cached Client.
	ProviderNamespace string
}

func (c ClientCacheStorageStoreRequest) Validate() error {
	var err error
	if c.Client == nil {
		err = errors.Join(err, fmt.Errorf("a Client must be set"))
	}

	return err
}

type PruneFilterFunc func(secret corev1.Secret) bool

var _ ClientCacheStorage = (*defaultClientCacheStorage)(nil)

type ClientCacheStorage interface {
	Store(context.Context, ctrlclient.Client, ClientCacheStorageStoreRequest) (*corev1.Secret, error)
	Restore(context.Context, ctrlclient.Client, ClientCacheStorageRestoreRequest) (*clientCacheStorageEntry, error)
	RestoreAll(context.Context, ctrlclient.Client, ClientCacheStorageRestoreAllRequest) ([]*clientCacheStorageEntry, error)
	Prune(context.Context, ctrlclient.Client, ClientCacheStoragePruneRequest) (int, error)
	Purge(context.Context, ctrlclient.Client) error
}

type defaultClientCacheStorage struct {
	hmacSecretObjKey  ctrlclient.ObjectKey
	hmacKey           []byte
	enforceEncryption bool
	logger            logr.Logger
	mu                sync.RWMutex
}

func (c *defaultClientCacheStorage) getSecret(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	if err := client.Get(ctx, key, s); err != nil {
		return nil, err
	}

	return s, nil
}

func (c *defaultClientCacheStorage) Store(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageStoreRequest) (*corev1.Secret, error) {
	logger := log.FromContext(ctx)
	if err := req.Validate(); err != nil {
		return nil, err
	}

	authObj := req.Client.GetVaultAuthObj()
	connObj := req.Client.GetVaultConnectionObj()
	credentialProvider := req.Client.GetCredentialProvider()
	cacheKey, err := req.Client.GetCacheKey()
	if err != nil {
		return nil, err
	}

	if c.enforceEncryption && (req.EncryptionClient == nil || req.EncryptionVaultAuth == nil) {
		return nil, fmt.Errorf("request is invalid for when enforcing encryption")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// global encryption policy checks, all requests must require encryption
	logger.Info("ClientCacheStorage.Store()",
		"enforceEncryption", c.enforceEncryption)

	labels := ctrlclient.MatchingLabels{
		// cacheKey is the key used to access a Client from the ClientCache
		labelCacheKey: cacheKey.String(),
		// required for storage cache cleanup performed by the Client's VaultAuth
		// this is done by controllers.VaultAuthReconciler
		labelAuthNamespace:  authObj.Namespace,
		labelAuthUID:        string(authObj.UID),
		labelAuthGeneration: strconv.FormatInt(authObj.Generation, 10),
		// required for storage cache cleanup performed by the Client's VaultConnect
		// this is done by controllers.VaultConnectionReconciler
		labelConnectionNamespace:  connObj.Namespace,
		labelConnectionUID:        string(connObj.UID),
		labelConnectionGeneration: strconv.FormatInt(connObj.Generation, 10),
		labelProviderUID:          string(credentialProvider.GetUID()),
		labelProviderNamespace:    credentialProvider.GetNamespace(),
	}
	s := &corev1.Secret{
		// we always store Clients in an Immutable secret as an anti-tampering mitigation.
		Immutable: pointer.Bool(true),
		ObjectMeta: metav1.ObjectMeta{
			Name:            fmt.Sprintf(NamePrefixVCC + cacheKey.String()),
			Namespace:       common.OperatorNamespace,
			OwnerReferences: req.OwnerReferences,
			Labels:          c.addCommonMatchingLabels(labels),
		},
	}

	sec := req.Client.GetTokenSecret()
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(sec)
	if err != nil {
		return nil, err
	}

	if c.enforceEncryption {
		// needed for restoration
		s.ObjectMeta.Labels[labelEncrypted] = "true"
		s.ObjectMeta.Labels[labelVaultTransitRef] = req.EncryptionVaultAuth.Name

		mount := req.EncryptionVaultAuth.Spec.StorageEncryption.Mount
		keyName := req.EncryptionVaultAuth.Spec.StorageEncryption.KeyName
		encBytes, err := EncryptWithTransit(ctx, req.EncryptionClient, mount, keyName, b)
		if err != nil {
			return nil, err
		}
		b = encBytes
	}

	s.Data = map[string][]byte{
		fieldCachedSecret: b,
	}
	message, err := c.message(s.Name, cacheKey.String(), b)
	if err != nil {
		return nil, err
	}

	messageMAC, err := macMessage(c.hmacKey, message)
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

			// we want to retry create since the previous Delete() call is eventually consistent.
			bo := backoff.NewExponentialBackOff()
			bo.MaxInterval = 2 * time.Second
			if err := backoff.Retry(func() error {
				return client.Create(ctx, s)
			}, backoff.WithMaxRetries(bo, 5)); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return s, nil
}

func (c *defaultClientCacheStorage) Restore(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageRestoreRequest) (*clientCacheStorageEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	s, err := c.getSecret(ctx, client, req.SecretObjKey)
	if err != nil {
		return nil, err
	}

	return c.restore(ctx, req, s)
}

func (c *defaultClientCacheStorage) restore(ctx context.Context, req ClientCacheStorageRestoreRequest, s *corev1.Secret) (*clientCacheStorageEntry, error) {
	if err := c.validateSecretMAC(req, s); err != nil {
		return nil, err
	}

	var secret *api.Secret
	if b, ok := s.Data[fieldCachedSecret]; ok {
		transitRef := s.Labels["vaultTransitRef"]
		if transitRef != "" {
			if req.DecryptionClient == nil || req.DecryptionVaultAuth == nil {
				return nil, fmt.Errorf("request is invalid for decryption")
			}

			if req.DecryptionVaultAuth.Name != transitRef {
				return nil, fmt.Errorf("invalid vaultTransitRef, need %s, have %s", transitRef, req.DecryptionVaultAuth.Name)
			}

			mount := req.DecryptionVaultAuth.Spec.StorageEncryption.Mount
			keyName := req.DecryptionVaultAuth.Spec.StorageEncryption.KeyName
			decBytes, err := DecryptWithTransit(ctx, req.DecryptionClient, mount, keyName, b)
			if err != nil {
				return nil, err
			}

			b = decBytes
		}

		if err := json.Unmarshal(b, &secret); err != nil {
			return nil, err
		}
	}

	entry := &clientCacheStorageEntry{
		CacheKey:                 req.CacheKey,
		VaultSecret:              secret,
		VaultAuthUID:             types.UID(s.Labels[labelAuthUID]),
		VaultAuthNamespace:       s.Labels[labelAuthNamespace],
		VaultConnectionUID:       types.UID(s.Labels[labelConnectionUID]),
		VaultConnectionNamespace: s.Labels[labelConnectionNamespace],
		ProviderUID:              types.UID(s.Labels[labelProviderUID]),
		ProviderNamespace:        s.Labels[labelProviderNamespace],
	}

	if v, ok := s.Labels[labelAuthGeneration]; ok && v != "" {
		generation, err := strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		entry.VaultAuthGeneration = int64(generation)
	}

	if v, ok := s.Labels[labelConnectionGeneration]; ok && v != "" {
		generation, err := strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		entry.VaultConnectionGeneration = int64(generation)
	}

	return entry, nil
}

func (c *defaultClientCacheStorage) Prune(ctx context.Context, client ctrlclient.Client, req ClientCacheStoragePruneRequest) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	secrets := &corev1.SecretList{}
	if err := client.List(ctx, secrets, req.MatchingLabels, ctrlclient.InNamespace(common.OperatorNamespace)); err != nil {
		return 0, nil
	}

	var errs error
	var count int
	for _, item := range secrets.Items {
		if req.Filter != nil && req.Filter(item) {
			continue
		}

		if err := client.Delete(ctx, &item); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}

			errs = errors.Join(errs, err)
			continue
		}
		count++
	}

	c.logger.V(consts.LogLevelDebug).Info("Pruned storage cache", "count", count, "total", len(secrets.Items))

	return count, errs
}

// Purge all cached client Secrets. This should only be called when transitioning from persistence to non-persistence modes.
func (c *defaultClientCacheStorage) Purge(ctx context.Context, client ctrlclient.Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return client.DeleteAllOf(ctx, &corev1.Secret{}, c.deleteAllOfOptions()...)
}

func (c *defaultClientCacheStorage) RestoreAll(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageRestoreAllRequest) ([]*clientCacheStorageEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var errs error

	found := &corev1.SecretList{}
	if err := client.List(ctx, found, c.listOptions()...); err != nil {
		return nil, err
	}

	var result []*clientCacheStorageEntry
	for _, s := range found.Items {
		cacheKey := ClientCacheKey(s.Labels[labelCacheKey])
		req := ClientCacheStorageRestoreRequest{
			SecretObjKey:        ctrlclient.ObjectKeyFromObject(&s),
			CacheKey:            cacheKey,
			DecryptionClient:    req.DecryptionClient,
			DecryptionVaultAuth: req.DecryptionVaultAuth,
		}

		entry, err := c.restore(ctx, req, &s)
		if err != nil {
			errs = errors.Join(errs, err)
		}

		result = append(result, entry)
	}

	return result, errs
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

	ok, _, err = validateMAC(message, messageMAC, c.hmacKey)
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

func (c *defaultClientCacheStorage) deleteAllOfOptions() []ctrlclient.DeleteAllOfOption {
	var result []ctrlclient.DeleteAllOfOption
	for _, opt := range c.listOptions() {
		result = append(result, opt.(ctrlclient.DeleteAllOfOption))
	}
	return result
}

func (c *defaultClientCacheStorage) listOptions() []ctrlclient.ListOption {
	return []ctrlclient.ListOption{
		c.commonMatchingLabels(),
		// We may want to reconsider constraining the purge to the OperatorNamespace,
		// for example if the Operator is moved from one Namespace to another.
		ctrlclient.InNamespace(common.OperatorNamespace),
	}
}

func (c *defaultClientCacheStorage) commonMatchingLabels() ctrlclient.MatchingLabels {
	return ctrlclient.MatchingLabels{
		"app.kubernetes.io/name":       "vault-secrets-operator",
		"app.kubernetes.io/managed-by": "vso",
		"app.kubernetes.io/component":  "client-cache-storage",
	}
}

func (c *defaultClientCacheStorage) addCommonMatchingLabels(labels ctrlclient.MatchingLabels) ctrlclient.MatchingLabels {
	for k, v := range c.commonMatchingLabels() {
		labels[k] = v
	}

	return labels
}

type ClientCacheStorageConfig struct {
	// EnforceEncryption for persisting Clients i.e. the controller must have VaultTransitRef
	// configured before it will persist the Client to storage. This option requires Persist to be true.
	EnforceEncryption bool
	HMACSecretObjKey  ctrlclient.ObjectKey
}

func DefaultClientCacheStorageConfig() *ClientCacheStorageConfig {
	return &ClientCacheStorageConfig{
		EnforceEncryption: false,
		HMACSecretObjKey: ctrlclient.ObjectKey{
			Name:      NamePrefixVCC + "storage-hmac-key",
			Namespace: common.OperatorNamespace,
		},
	}
}

func NewDefaultClientCacheStorage(ctx context.Context, client ctrlclient.Client, config *ClientCacheStorageConfig) (ClientCacheStorage, error) {
	if err := validateObjectKey(config.HMACSecretObjKey); err != nil {
		return nil, err
	}

	s, err := createHMACKeySecret(ctx, client, config.HMACSecretObjKey)
	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}

	if s == nil {
		s, err = getHMACKeySecret(ctx, client, config.HMACSecretObjKey)
		if err != nil {
			return nil, err
		}
	}

	return &defaultClientCacheStorage{
		hmacSecretObjKey:  config.HMACSecretObjKey,
		hmacKey:           s.Data[hmacKeyName],
		enforceEncryption: config.EnforceEncryption,
		logger:            zap.New().WithName("ClientCacheStorage"),
	}, nil
}

func validateObjectKey(key ctrlclient.ObjectKey) error {
	if key.Name == "" || key.Namespace == "" {
		return InvalidObjectKeyError
	}
	return nil
}
