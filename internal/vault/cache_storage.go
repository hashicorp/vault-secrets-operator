// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/pointer"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const (
	labelEncrypted       = "encrypted"
	labelVaultTransitRef = "vaultTransitRef"
	labelCacheKey        = "cacheKey"
	labelTokenAccessor   = "vaultTokenAccessor"
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

// commonMatchingLabels are included in all stored Clients. They are used for
// nearly all client cache functions. Ideally they should never be altered,
// since it could lead to orphaned cache entries and possibly other issues.
var commonMatchingLabels = ctrlclient.MatchingLabels{
	"app.kubernetes.io/name":       "vault-secrets-operator",
	"app.kubernetes.io/managed-by": "vso",
	"app.kubernetes.io/component":  "client-cache-storage",
}

func IsStorageEntryNotFoundErr(err error) bool {
	return apierrors.IsNotFound(err)
}

type ClientCacheStorageStoreRequest struct {
	OwnerReferences     []metav1.OwnerReference
	Client              Client
	EncryptionClient    Client
	EncryptionVaultAuth *secretsv1beta1.VaultAuth
	// IncludeTokenAccessor is used for testing only, not for production. Exposing
	// the token accessor in the Secret is a security risk.
	IncludeTokenAccessor bool
}

type ClientCacheStoragePruneRequest struct {
	MatchingLabels ctrlclient.MatchingLabels
	Filter         PruneFilterFunc
}

type CachingClientFactoryShutDownRequest struct {
	Revoke bool
}

type ClientCacheStorageRestoreRequest struct {
	SecretObjKey        ctrlclient.ObjectKey
	CacheKey            ClientCacheKey
	DecryptionClient    Client
	DecryptionVaultAuth *secretsv1beta1.VaultAuth
	// NoPruneOnError preserves the storage entry on restoration error.
	NoPruneOnError bool
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
	} else {
		if c.Client.IsClone() {
			err = errors.Join(err, fmt.Errorf("cloned Clients cannot be stored"))
		}
	}

	return err
}

type PruneFilterFunc func(secret corev1.Secret) bool

var _ ClientCacheStorage = (*defaultClientCacheStorage)(nil)

type ClientCacheStorage interface {
	Store(context.Context, ctrlclient.Client, ClientCacheStorageStoreRequest) (*corev1.Secret, error)
	Restore(context.Context, ctrlclient.Client, ClientCacheStorageRestoreRequest) (*clientCacheStorageEntry, error)
	Prune(context.Context, ctrlclient.Client, ClientCacheStoragePruneRequest) (int, error)
	Purge(context.Context, ctrlclient.Client) error
	Len(context.Context, ctrlclient.Client) (int, error)
}

type defaultClientCacheStorage struct {
	hmacKey                  []byte
	enforceEncryption        bool
	logger                   logr.Logger
	requestCounterVec        *prometheus.CounterVec
	requestErrorCounterVec   *prometheus.CounterVec
	operationCounterVec      *prometheus.CounterVec
	operationErrorCounterVec *prometheus.CounterVec
	mu                       sync.RWMutex
}

func (c *defaultClientCacheStorage) getSecret(ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	if err := client.Get(ctx, key, s); err != nil {
		return nil, err
	}

	return s, nil
}

func (c *defaultClientCacheStorage) Store(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageStoreRequest) (*corev1.Secret, error) {
	logger := log.FromContext(ctx).V(consts.LogLevelDebug).WithName("clientCacheStorage")
	var err error
	defer func() {
		c.incrementRequestCounter(metrics.OperationStore, err)
		// track the store operation metrics to be in line with bulk operations like restore, prune, etc.
		c.incrementOperationCounter(metrics.OperationStore, err)
	}()

	err = req.Validate()
	if err != nil {
		return nil, err
	}

	authObj := req.Client.GetVaultAuthObj()
	connObj := req.Client.GetVaultConnectionObj()
	credentialProvider := req.Client.GetCredentialProvider()

	var cacheKey ClientCacheKey
	cacheKey, err = req.Client.GetCacheKey()
	if err != nil {
		return nil, err
	}

	if c.enforceEncryption && (req.EncryptionClient == nil || req.EncryptionVaultAuth == nil) {
		err = fmt.Errorf("request is invalid for when enforcing encryption")
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	logger.Info("Storing client",
		"enforceEncryption", c.enforceEncryption,
		"cacheKey", cacheKey)

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

	// used for testing only, not for production. Exposing the token accessor in the
	// Secret is a security risk.
	if req.IncludeTokenAccessor {
		accessor, err := req.Client.GetTokenSecret().TokenAccessor()
		if err == nil {
			labels[labelTokenAccessor] = accessor
		}
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

	var b []byte
	b, err = json.Marshal(sec)
	if err != nil {
		return nil, err
	}

	if c.enforceEncryption {
		// needed for restoration
		s.ObjectMeta.Labels[labelEncrypted] = "true"
		s.ObjectMeta.Labels[labelVaultTransitRef] = req.EncryptionVaultAuth.Name

		mount := req.EncryptionVaultAuth.Spec.StorageEncryption.Mount
		keyName := req.EncryptionVaultAuth.Spec.StorageEncryption.KeyName
		var encBytes []byte
		encBytes, err = EncryptWithTransit(ctx, req.EncryptionClient, mount, keyName, b)
		if err != nil {
			return nil, err
		}
		b = encBytes
	}

	s.Data = map[string][]byte{
		fieldCachedSecret: b,
	}
	var message []byte
	message, err = c.message(s.Name, cacheKey.String(), b)
	if err != nil {
		return nil, err
	}

	var messageMAC []byte
	messageMAC, err = helpers.MACMessage(c.hmacKey, message)
	if err != nil {
		return nil, err
	}

	s.Data[fieldMACMessage] = messageMAC
	if e := client.Create(ctx, s); e != nil {
		if apierrors.IsAlreadyExists(e) {
			// since the Secret is immutable we need to always recreate it
			err = c.delete(ctx, client, s)
			if err != nil {
				return nil, err
			}

			// we want to retry create since the previous Delete() call is eventually consistent.
			bo := backoff.NewExponentialBackOff()
			bo.MaxInterval = 2 * time.Second
			err = backoff.Retry(func() error {
				return client.Create(ctx, s)
			}, backoff.WithMaxRetries(bo, 5))
			if err != nil {
				return nil, err
			}
		} else {
			err = e
			logger.Error(err, "Failed to store client",
				"enforceEncryption", c.enforceEncryption,
				"cacheKey", cacheKey, "secret", ctrlclient.ObjectKeyFromObject(s))
			return nil, err
		}
	}

	logger.Info("Stored client",
		"enforceEncryption", c.enforceEncryption,
		"cacheKey", cacheKey, "secret", ctrlclient.ObjectKeyFromObject(s))

	return s, nil
}

func (c *defaultClientCacheStorage) Restore(ctx context.Context, client ctrlclient.Client, req ClientCacheStorageRestoreRequest) (*clientCacheStorageEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var err error
	defer func() {
		c.incrementRequestCounter(metrics.OperationRestore, err)
	}()

	err = common.ValidateObjectKey(req.SecretObjKey)
	if err != nil {
		return nil, err
	}

	var secret *corev1.Secret
	secret, err = c.getSecret(ctx, client, req.SecretObjKey)
	if err != nil {
		return nil, err
	}

	var entry *clientCacheStorageEntry
	entry, err = c.restore(ctx, client, req, secret)
	return entry, err
}

func (c *defaultClientCacheStorage) Len(ctx context.Context, client ctrlclient.Client) (int, error) {
	found, err := c.listSecrets(ctx, client, c.listOptions()...)
	if err != nil {
		return 0, err
	}

	return len(found), nil
}

func (c *defaultClientCacheStorage) restore(ctx context.Context, client ctrlclient.Client,
	req ClientCacheStorageRestoreRequest, s *corev1.Secret,
) (*clientCacheStorageEntry, error) {
	var err error
	defer func() {
		var errs error
		if err != nil {
			errs = errors.Join(errs, err)
			if !req.NoPruneOnError {
				errs = errors.Join(errs, c.delete(ctx, client, s))
			}
		}

		c.incrementOperationCounter(metrics.OperationRestore, errs)
	}()

	var secret *api.Secret
	err = c.validateSecretMAC(req, s)
	if err != nil {
		return nil, err
	}

	if b, ok := s.Data[fieldCachedSecret]; ok {
		transitRef := s.Labels["vaultTransitRef"]
		if transitRef != "" {
			if req.DecryptionClient == nil || req.DecryptionVaultAuth == nil {
				err = fmt.Errorf("request is invalid for decryption")
				return nil, err
			}

			if req.DecryptionVaultAuth.Name != transitRef {
				err = fmt.Errorf("invalid vaultTransitRef, need %s, have %s", transitRef, req.DecryptionVaultAuth.Name)
				return nil, err
			}

			mount := req.DecryptionVaultAuth.Spec.StorageEncryption.Mount
			keyName := req.DecryptionVaultAuth.Spec.StorageEncryption.KeyName
			var decBytes []byte
			decBytes, err = DecryptWithTransit(ctx, req.DecryptionClient, mount, keyName, b)
			if err != nil {
				return nil, err
			}

			b = decBytes
		}

		err = json.Unmarshal(b, &secret)
		if err != nil {
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
		var generation int
		generation, err = strconv.Atoi(v)
		if err != nil {
			return nil, err
		}
		entry.VaultAuthGeneration = int64(generation)
	}

	if v, ok := s.Labels[labelConnectionGeneration]; ok && v != "" {
		var generation int
		generation, err = strconv.Atoi(v)
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

	var errs error
	defer func() {
		c.incrementRequestCounter(metrics.OperationPrune, errs)
	}()

	if len(req.MatchingLabels) == 0 {
		errs = errors.Join(fmt.Errorf("prune request requires at least one matching label"))
		return 0, errs
	}

	secrets, err := c.listSecrets(ctx, client, req.MatchingLabels, ctrlclient.InNamespace(common.OperatorNamespace))
	if err != nil {
		return 0, errors.Join(err)
	}

	var count int
	for _, item := range secrets {
		if req.Filter != nil && req.Filter(item) {
			continue
		}

		if err := c.delete(ctx, client, &item); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		count++
	}

	c.logger.V(consts.LogLevelDebug).Info("Pruned storage cache", "count", count, "total", len(secrets))

	return count, errs
}

func (c *defaultClientCacheStorage) delete(ctx context.Context, client ctrlclient.Client, secret *corev1.Secret) error {
	var errs error
	defer func() {
		c.incrementRequestCounter(metrics.OperationDelete, errs)
	}()

	if secret == nil {
		errs = errors.Join(errs, fmt.Errorf("secret cannot be nil"))
		return errs
	}

	if err := client.Delete(ctx, secret); err != nil {
		if !apierrors.IsNotFound(err) {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (c *defaultClientCacheStorage) listSecrets(ctx context.Context, client ctrlclient.Client, listOptions ...ctrlclient.ListOption) ([]corev1.Secret, error) {
	secrets := &corev1.SecretList{}
	if err := client.List(ctx, secrets, listOptions...); err != nil {
		return nil, err
	}
	return secrets.Items, nil
}

// Purge all cached client Secrets. This should only be called when transitioning from persistence to non-persistence modes.
func (c *defaultClientCacheStorage) Purge(ctx context.Context, client ctrlclient.Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	defer func() {
		c.incrementRequestCounter(metrics.OperationPurge, err)
	}()

	err = client.DeleteAllOf(ctx, &corev1.Secret{}, c.deleteAllOfOptions()...)
	return err
}

func (c *defaultClientCacheStorage) validateSecretMAC(req ClientCacheStorageRestoreRequest, s *corev1.Secret) error {
	if s == nil {
		return fmt.Errorf("secret is nil")
	}

	var missingFields []string
	b, ok := s.Data[fieldCachedSecret]
	if !ok {
		missingFields = append(missingFields, fieldCachedSecret)
	}

	messageMAC, ok := s.Data[fieldMACMessage]
	if !ok {
		missingFields = append(missingFields, fieldMACMessage)
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("secret data for %q missing required fields: %v",
			ctrlclient.ObjectKeyFromObject(s), missingFields)
	}

	message, err := c.message(s.Name, req.CacheKey.String(), b)
	if err != nil {
		return err
	}

	ok, _, err = helpers.ValidateMAC(message, messageMAC, c.hmacKey)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("invalid message MAC for secret %q",
			ctrlclient.ObjectKeyFromObject(s))
	}

	return nil
}

func (c *defaultClientCacheStorage) message(name, cacheKey string, secretData []byte) ([]byte, error) {
	if name == "" || cacheKey == "" {
		return nil, fmt.Errorf("invalid empty name or cacheKey")
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
	return commonMatchingLabels
}

func (c *defaultClientCacheStorage) addCommonMatchingLabels(labels ctrlclient.MatchingLabels) ctrlclient.MatchingLabels {
	for k, v := range c.commonMatchingLabels() {
		labels[k] = v
	}

	return labels
}

func (c *defaultClientCacheStorage) incrementRequestCounter(operation string, err error) {
	if err != nil {
		c.requestErrorCounterVec.WithLabelValues(operation).Inc()
	} else {
		c.requestCounterVec.WithLabelValues(operation).Inc()
	}
}

func (c *defaultClientCacheStorage) incrementOperationCounter(operation string, err error) {
	if err != nil {
		c.operationErrorCounterVec.WithLabelValues(operation).Inc()
	} else {
		c.operationCounterVec.WithLabelValues(operation).Inc()
	}
}

type ClientCacheStorageConfig struct {
	// EnforceEncryption for persisting Clients i.e. the controller must have VaultTransitRef
	// configured before it will persist the Client to storage. This option requires Persist to be true.
	EnforceEncryption bool
	HMACSecretObjKey  ctrlclient.ObjectKey
	OwnerRefs         []metav1.OwnerReference
	// skipHMACSecret is used for unit tests, which need to control various aspects
	// of HMAC secret creation.
	skipHMACSecret bool
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

func NewDefaultClientCacheStorage(ctx context.Context, client ctrlclient.Client,
	config *ClientCacheStorageConfig, metricsRegistry prometheus.Registerer,
) (ClientCacheStorage, error) {
	return newDefaultClientCacheStorage(ctx, client, config, metricsRegistry)
}

func newDefaultClientCacheStorage(ctx context.Context, client ctrlclient.Client,
	config *ClientCacheStorageConfig, metricsRegistry prometheus.Registerer,
) (*defaultClientCacheStorage, error) {
	if config == nil {
		config = DefaultClientCacheStorageConfig()
	}

	cacheStorage := &defaultClientCacheStorage{
		enforceEncryption: config.EnforceEncryption,
		logger:            zap.New().WithName("ClientCacheStorage"),
		requestCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientCacheStorageReqsTotal,
				Help: "Client storage cache request total",
			}, []string{
				metrics.LabelOperation,
			},
		),
		requestErrorCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientCacheStorageReqsErrorsTotal,
				Help: "Client storage cache request errors",
			}, []string{
				metrics.LabelOperation,
			},
		),
		operationCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientCacheStorageOpsTotal,
				Help: "Client storage cache operations",
			}, []string{
				metrics.LabelOperation,
			},
		),
		operationErrorCounterVec: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricsFQNClientCacheStorageOpsErrorsTotal,
				Help: "Client storage cache operation errors",
			}, []string{
				metrics.LabelOperation,
			},
		),
	}

	if !config.skipHMACSecret {
		if err := common.ValidateObjectKey(config.HMACSecretObjKey); err != nil {
			return nil, err
		}

		s, err := helpers.CreateHMACKeySecret(ctx, client, config.HMACSecretObjKey)
		if err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return nil, err
			}
		}

		if s == nil {
			s, err = helpers.GetHMACKeySecret(ctx, client, config.HMACSecretObjKey)
			if err != nil {
				return nil, err
			}
		}

		cacheStorage.hmacKey = s.Data[helpers.HMACKeyName]
	}

	if metricsRegistry != nil {
		// metric for exporting the storage cache configuration
		configGauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricsFQNClientCacheStorageConfig,
			Help: "Client storage cache config",
			ConstLabels: map[string]string{
				metricsLabelEnforceEncryption: strconv.FormatBool(cacheStorage.enforceEncryption),
			},
		})
		configGauge.Set(1)
		metricsRegistry.MustRegister(
			configGauge,
			cacheStorage.requestCounterVec,
			cacheStorage.requestErrorCounterVec,
			cacheStorage.operationCounterVec,
			cacheStorage.operationErrorCounterVec,
			newClientCacheStorageCollector(cacheStorage, ctx, client),
		)
	}

	return cacheStorage, nil
}
