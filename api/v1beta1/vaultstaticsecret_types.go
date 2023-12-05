// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultStaticSecretSpec defines the desired state of VaultStaticSecret
type VaultStaticSecretSpec struct {
	// VaultAuthRef to the VaultAuth resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultAuthRefB`. If no namespace prefix is provided it will default to
	// namespace of the VaultAuth CR. If no value is specified for VaultAuthRef the Operator will
	// default to the `default` VaultAuth, configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace to get the secret from in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount for the secret in Vault
	Mount string `json:"mount"`
	// Path of the secret in Vault, corresponds to the `path` parameter for,
	// kv-v1: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#read-secret
	// kv-v2: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version
	Path string `json:"path"`
	// Version of the secret to fetch. Only valid for type kv-v2. Corresponds to version query parameter:
	// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#version
	// +kubebuilder:validation:Minimum=0
	Version int `json:"version,omitempty"`
	// Type of the Vault static secret
	// +kubebuilder:validation:Enum={kv-v1,kv-v2}
	Type string `json:"type"`
	// RefreshAfter a period of time, in duration notation e.g. 30s, 1m, 24h
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(s|m|h))$"
	RefreshAfter string `json:"refreshAfter,omitempty"`
	// HMACSecretData determines whether the Operator computes the
	// HMAC of the Secret's data. The MAC value will be stored in
	// the resource's Status.SecretMac field, and will be used for drift detection
	// and during incoming Vault secret comparison.
	// Enabling this feature is recommended to ensure that Secret's data stays consistent with Vault.
	// +kubebuilder:default=true
	HMACSecretData bool `json:"hmacSecretData,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// All configured targets wil be ignored if HMACSecretData is set to false.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination provides configuration necessary for syncing the Vault secret to Kubernetes.
	Destination Destination `json:"destination"`
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
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultStaticSecret is the Schema for the vaultstaticsecrets API
type VaultStaticSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultStaticSecretSpec   `json:"spec,omitempty"`
	Status VaultStaticSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultStaticSecretList contains a list of VaultStaticSecret
type VaultStaticSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultStaticSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultStaticSecret{}, &VaultStaticSecretList{})
}
