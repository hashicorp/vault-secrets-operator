// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package consts

const (
	ReasonAccepted                  = "Accepted"
	ReasonCacheRestorationFailed    = "CacheRestorationFailed"
	ReasonCacheRestorationSucceeded = "CacheRestorationSucceeded"
	ReasonClientTokenNotInCache     = "ClientTokenNotInCache"
	ReasonClientTokenRenewal        = "ClientTokenRenewal"
	ReasonConnectionNotFound        = "ConnectionNotFound"
	ReasonErrorGettingRef           = "ErrorGettingRef"
	ReasonInvalidAuthConfiguration  = "InvalidAuthConfiguration"
	ReasonInvalidCacheKey           = "InvalidCacheKey"
	ReasonInvalidConnection         = "InvalidVaultConnection"
	ReasonInvalidHorizon            = "InvalidHorizon"
	ReasonInvalidLeaseError         = "InvalidLeaseError"
	ReasonInvalidResourceRef        = "InvalidResourceRef"
	ReasonInvalidTokenTTL           = "InvalidTokenTTL"
	ReasonK8sClientError            = "K8sClientError"
	ReasonMaxCacheMisses            = "MaxCacheMisses"
	ReasonPersistenceFailed         = "PersistenceFailed"
	ReasonPersistenceForbidden      = "PersistenceForbidden"
	ReasonPersistentCacheCleanup    = "PersistentCacheCleanup"
	ReasonSecretLeaseRenewal        = "SecretLeaseRenewal"
	ReasonSecretLeaseRenewalError   = "SecretLeaseRenewalError"
	ReasonSecretRotated             = "SecretRotated"
	ReasonSecretSyncError           = "SecretSyncError"
	ReasonSecretSynced              = "SecretSynced"
	ReasonStatusUpdateError         = "StatusUpdateError"
	ReasonTokenLookupError          = "TokenLookupError"
	ReasonTransitDecryptError       = "TransitDecryptError"
	ReasonTransitDecryptSuccessful  = "TransitDecryptSuccessful"
	ReasonTransitEncryptError       = "TransitEncryptError"
	ReasonTransitEncryptSuccessful  = "TransitEncryptSuccessful"
	ReasonTransitError              = "TransitError"
	ReasonUnrecoverable             = "Unrecoverable"
	ReasonVaultClientCacheCreation  = "VaultClientCacheCreation"
	ReasonVaultClientCacheEviction  = "VaultClientCacheEviction"
	ReasonVaultClientConfigError    = "VaultClientConfigError"
	ReasonVaultClientError          = "VaultClientError"
	ReasonVaultClientInstantiation  = "VaultClientCacheInstantiation"
	ReasonVaultStaticSecret         = "VaultStaticSecretError"
)
