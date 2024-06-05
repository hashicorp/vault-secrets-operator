// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package consts

const (
	ReasonAccepted                   = "Accepted"
	ReasonInvalidConfiguration       = "InvalidConfiguration"
	ReasonInvalidResourceRef         = "InvalidResourceRef"
	ReasonK8sClientError             = "K8sClientError"
	ReasonRolloutRestartFailed       = "RolloutRestartFailed"
	ReasonRolloutRestartTriggered    = "RolloutRestartTriggered"
	ReasonRolloutRestartUnsupported  = "RolloutRestartUnsupported"
	ReasonSecretLeaseRenewal         = "SecretLeaseRenewal"
	ReasonSecretLeaseRevoke          = "SecretLeaseRevoke"
	ReasonSecretLeaseRenewalError    = "SecretLeaseRenewalError"
	ReasonSecretRotated              = "SecretRotated"
	ReasonSecretSync                 = "SecretSync"
	ReasonSecretSyncError            = "SecretSyncError"
	ReasonSecretSynced               = "SecretSynced"
	ReasonStatusUpdateError          = "StatusUpdateError"
	ReasonUnrecoverable              = "Unrecoverable"
	ReasonVaultClientConfigError     = "VaultClientConfigError"
	ReasonVaultClientError           = "VaultClientError"
	ReasonVaultStaticSecret          = "VaultStaticSecretError"
	ReasonSecretDataDrift            = "SecretDataDrift"
	ReasonInexistentDestination      = "InexistentDestination"
	ReasonResourceUpdated            = "ResourceUpdated"
	ReasonInitialSync                = "InitialSync"
	ReasonInRenewalWindow            = "InRenewalWindow"
	ReasonHMACDataError              = "HMACDataError"
	ReasonCertificateRevocationError = "CertificateRevocationError"
	ReasonTransformationError        = "TransformationError"
	ReasonSecretDataBuilderError     = "SecretDataBuilderError"
	ReasonForceSync                  = "ForceSync"
	ReasonVaultTokenRotated          = "VaultTokenRotated"
	ReasonVaultClientConfigChanged   = "VaultClientConfigChanged"
)
