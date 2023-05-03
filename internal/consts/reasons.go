// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package consts

const (
	ReasonAccepted                = "Accepted"
	ReasonInvalidConfiguration    = "InvalidConfiguration"
	ReasonInvalidResourceRef      = "InvalidResourceRef"
	ReasonK8sClientError          = "K8sClientError"
	ReasonRolloutRestartFailed    = "RolloutRestartFailed"
	ReasonRolloutRestartTriggered = "RolloutRestartTriggered"
	ReasonSecretLeaseRenewal      = "SecretLeaseRenewal"
	ReasonSecretLeaseRevoke       = "SecretLeaseRevoke"
	ReasonSecretLeaseRenewalError = "SecretLeaseRenewalError"
	ReasonSecretRotated           = "SecretRotated"
	ReasonSecretSync              = "SecretSync"
	ReasonSecretSyncError         = "SecretSyncError"
	ReasonSecretSynced            = "SecretSynced"
	ReasonStatusUpdateError       = "StatusUpdateError"
	ReasonUnrecoverable           = "Unrecoverable"
	ReasonVaultClientConfigError  = "VaultClientConfigError"
	ReasonVaultClientError        = "VaultClientError"
	ReasonVaultStaticSecret       = "VaultStaticSecretError"
)
