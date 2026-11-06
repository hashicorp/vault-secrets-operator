// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultStaticSecretSpec defines the desired state of VaultStaticSecret
// +kubebuilder:validation:XValidation:rule="has(self.path) || (has(self.data) && size(self.data) > 0)",message="one of path or data must be set"
type VaultStaticSecretSpec struct {
	// VaultAuthRef to the VaultAuth resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultAuthRefB`. If no namespace prefix is provided it will default to the
	// namespace of the VaultAuth CR. If no value is specified for VaultAuthRef the Operator will
	// default to the `default` VaultAuth, configured in the operator's namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace of the secrets engine mount in Vault. If not set, the namespace that's
	// part of VaultAuth resource will be inferred.
	Namespace string `json:"namespace,omitempty"`
	// RefreshAfter a period of time, in duration notation e.g. 30s, 1m, 24h
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(s|m|h))$`
	RefreshAfter string `json:"refreshAfter,omitempty"`
	// HMACSecretData determines whether the Operator computes the
	// HMAC of the Secret's data. The MAC value will be stored in
	// the resource's Status.SecretMac field, and will be used for drift detection
	// and during incoming Vault secret comparison.
	// Enabling this feature is recommended to ensure that Secret's data stays consistent with Vault.
	// +kubebuilder:default=true
	HMACSecretData *bool `json:"hmacSecretData,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// All configured targets will be ignored if HMACSecretData is set to false.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination provides configuration necessary for syncing the Vault secret to Kubernetes.
	Destination Destination `json:"destination"`
	// SyncConfig configures sync behavior from Vault to VSO
	SyncConfig *SyncConfig `json:"syncConfig,omitempty"`
	// Data aggregates individual keys from one or more Vault secrets into the
	// destination Kubernetes Secret. Each map entry maps a destination Secret
	// key to a Vault secret reference in the form `SECRET_PATH#KEY[#VERSION]`,
	// where SECRET_PATH is relative to Mount, KEY is a key within that Vault
	// secret, and VERSION is an optional kv-v2 secret version. All referenced
	// paths are read from the Mount configured on this resource.
	//
	// When Path is also set, the secret at Path is read first and the keys
	// resolved from Data are then overlaid on top of it, overwriting any
	// same-named keys.
	//
	// If a referenced path, key, or version cannot be resolved, the sync fails
	// and the reason is recorded in the resource's status.
	//
	// Note: when Data is set, the `_raw` key of the destination Secret holds
	// the aggregated secret data rather than the response of a single Vault
	// read.
	// +kubebuilder:validation:MinProperties=1
	Data map[string]string `json:"data,omitempty"`

	VaultStaticSecretCommon `json:",inline"`
}

type VaultStaticSecretCommon struct {
	// Mount for the secret in Vault
	Mount string `json:"mount"`
	// Path of the secret in Vault, corresponds to the `path` parameter for:
	// kv-v1: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret
	// kv-v2: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version
	// May only be omitted on a VaultStaticSecret that sets
	// VaultStaticSecretSpec.Data.
	// +optional
	Path string `json:"path,omitempty"`
	// Version of the secret to fetch. Only valid for type kv-v2. Corresponds to version query parameter:
	// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#version
	// This field should normally be omitted, unless you want to lock the sync to a specific version of the secret and ignore updates.
	// +kubebuilder:validation:Minimum=0
	Version int `json:"version,omitempty"`
	// Type of the Vault static secret
	// +kubebuilder:validation:Enum={kv-v1,kv-v2}
	Type string `json:"type"`
}

// VaultStaticSecretCollectable is a static secret collected into a CSI volume.
// Unlike VaultStaticSecretSpec it has no aggregation support, so Path remains
// required here.
// +kubebuilder:validation:XValidation:rule="has(self.path)",message="path must be set"
type VaultStaticSecretCollectable struct {
	VaultStaticSecretCommon `json:",inline"`
	// Transformation provides configuration for transforming the secret data before
	// it is stored in the CSI volume.
	Transformation *Transformation `json:"transformation,omitempty"`
}

// SyncConfig configures sync behavior from Vault to VSO
type SyncConfig struct {
	// InstantUpdates is a flag to indicate that event-driven updates are
	// enabled for this secret. When enabled, VSO subscribes to Vault's event
	// streaming API and reconciles immediately when a change is detected.
	// On event-triggered reconciles, VSO automatically attaches the
	// X-Vault-Index header to Vault requests to prevent stale reads on Vault
	// Performance Standbys. Requires Vault 1.20+ for X-Vault-Index support.
	InstantUpdates bool `json:"instantUpdates,omitempty"`
}

// VaultStaticSecretStatus defines the observed state of VaultStaticSecret
type VaultStaticSecretStatus struct {
	// LastGeneration is the Generation of the last reconciled resource.
	LastGeneration int64 `json:"lastGeneration"`
	// SecretMAC used when deciding whether new Vault secret data should be synced.
	//
	// The controller will compare the "new" Vault secret data to this value using HMAC,
	// if they are different, then the data will be synced to the Destination.
	//
	// The SecretMac is also used to detect drift in the Destination Secret's Data.
	// If drift is detected the data will be synced to the Destination.
	SecretMAC string `json:"secretMAC,omitempty"`
	// VaultClientMeta contains the status of the Vault client and is used during
	// resource reconciliation.
	VaultClientMeta VaultClientMeta `json:"vaultClientMeta,omitempty"`
	// Conditions hold information that can be used by other apps to determine the
	// health of the resource instance.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VaultStaticSecret is the Schema for the vaultstaticsecrets API
// +kubebuilder:printcolumn:name="Synced",type="string",JSONPath=`.status.conditions[?(@.type == "SecretSynced")].status`,description="secret sync status"
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=`.status.conditions[?(@.type == "Healthy")].status`,description="health status"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type == "Ready")].status`,description="resource ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`,description="resource age"
type VaultStaticSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultStaticSecretSpec   `json:"spec,omitempty"`
	Status VaultStaticSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultStaticSecretList contains a list of VaultStaticSecret
type VaultStaticSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultStaticSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultStaticSecret{}, &VaultStaticSecretList{})
}
