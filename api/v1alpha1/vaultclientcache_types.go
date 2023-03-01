// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// VaultClientCacheSpec defines the desired state of VaultClientCache.
// It is reserved for internal tracking of Vault client/token instances.
type VaultClientCacheSpec struct {
	// RenewalOffset relative to the TokenTTL. Should never be set to a value greater than TokenTTL.
	// If the value is 0, or unset, the controller will apply its own offset when computing the horizon
	// for the token renewal.
	// TODO: consider making this seconds instead
	RenewalOffset time.Duration `json:"renewalOffset,omitempty"`
	// VaultAuthRef to be used during cache restoration.
	VaultAuthRef string `json:"vaultAuthRef"`
	// VaultAuthNamespace to be used during cache restoration.
	VaultAuthNamespace string `json:"vaultAuthNamespace"`
	// VaultAuthMethod to be used during cache restoration.
	VaultAuthMethod string `json:"vaultAuthMethod"`
	// VaultAuthUID to validate against.
	VaultAuthUID types.UID `json:"vaultAuthUID"`
	// VaultAuthGeneration to validate against.
	VaultAuthGeneration int64 `json:"vaultAuthGeneration"`
	// VaultConnectionUID to validate against.
	VaultConnectionUID types.UID `json:"vaultConnectionUID"`
	// VaultConnectionGeneration to validate against.
	VaultConnectionGeneration int64 `json:"vaultConnectionGeneration"`
	// TargetNamespace to be used during cache restoration.
	TargetNamespace string `json:"targetNamespace"`
	// CredentialProviderUID to validate against.
	CredentialProviderUID types.UID `json:"credentialProviderUID,omitempty"`
	// MaxCacheMisses
	// +kubebuilder:default=30
	// +kubebuilder:validation:Maximum=300
	// MaxCacheMisses before this custom resource is no longer considered valid.
	// All invalid VaultClientCache resources will be deleted by the controller.
	MaxCacheMisses int `json:"maxCacheMisses,omitempty"` // CacheFetchInterval
	// +kubebuilder:default=5
	// +kubebuilder:validation:Maximum=30
	CacheFetchInterval int `json:"cacheFetchInterval,omitempty"`
	// VaultTransitRef is the name of a VaultTransit custom resource that will be used for
	// encryption/decryption of the cached client.
	VaultTransitRef string `json:"vaultTransitRef,omitempty"`
}

// VaultClientCacheStatus defines the observed state of VaultClientCache
type VaultClientCacheStatus struct {
	// RenewCount, or the number of token renewals completed.
	CacheSecretRef string `json:"cacheSecretRef"`
	CacheMisses    int    `json:"cacheMisses"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultClientCache is the Schema for the vaultclientcaches API
type VaultClientCache struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultClientCacheSpec   `json:"spec,omitempty"`
	Status VaultClientCacheStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultClientCacheList contains a list of VaultClientCache
type VaultClientCacheList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultClientCache `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultClientCache{}, &VaultClientCacheList{})
}
