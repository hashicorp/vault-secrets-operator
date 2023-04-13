// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultAuthConfigKubernetes provides VaultAuth configuration options needed for authenticating to Vault.
type VaultAuthConfigKubernetes struct {
	// Role to use for authenticating to Vault.
	Role string `json:"role"`
	// ServiceAccount to use when authenticating to Vault's kubernetes
	// authentication backend.
	ServiceAccount string `json:"serviceAccount"`
	// TokenAudiences to include in the ServiceAccount token.
	TokenAudiences []string `json:"audiences,omitempty"`
	// TokenExpirationSeconds to set the ServiceAccount token.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=600
	TokenExpirationSeconds int64 `json:"tokenExpirationSeconds,omitempty"`
}

// Token represents the token if present in a VaultAuthConfigJwt.
type Token struct {
	ValueFrom *corev1.EnvVarSource `json:"valueFrom"`
}

// VaultAuthConfigJwt provides VaultAuth configuration options needed for authenticating to Vault.
type VaultAuthConfigJwt struct {
	// Role to use for authenticating to Vault.
	Role string `json:"role"`
	// Token to use when authenticating to Vault's JWT authentication backend.
	Token *Token `json:"token,omitempty"`
	// ServiceAccount to use when creating a ServiceAccount token to authenticate to Vault's
	// JWT authentication backend.
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// TokenAudiences to include in the ServiceAccount token.
	TokenAudiences []string `json:"audiences,omitempty"`
	// TokenExpirationSeconds to set the ServiceAccount token.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=600
	TokenExpirationSeconds int64 `json:"tokenExpirationSeconds,omitempty"`
}

// VaultAuthSpec defines the desired state of VaultAuth
type VaultAuthSpec struct {
	// VaultConnectionRef of the corresponding VaultConnection CustomResource.
	// If no value is specified the Operator will default to the `default` VaultConnection,
	// configured in its own Kubernetes namespace.
	VaultConnectionRef string `json:"vaultConnectionRef,omitempty"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Method to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=kubernetes,jwt
	Method string `json:"method"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
	// Kubernetes specific auth configuration, requires that the Method be set to kubernetes.
	Kubernetes *VaultAuthConfigKubernetes `json:"kubernetes,omitempty"`
	// Jwt specific auth configuration, requires that the Method be set to jwt/oidc.
	Jwt *VaultAuthConfigJwt `json:"jwt,omitempty"`
	// StorageEncryption provides the necessary configuration to encrypt the client storage cache.
	// This should only be configured when client cache persistence with encryption is enabled.
	// This is done by passing setting the manager's commandline argument --client-cache-persistence-model=direct-encrypted
	// Typically there should only ever be one VaultAuth configured with StorageEncryption in the Cluster, and it should have the
	// the label: cacheStorageEncryption=true
	StorageEncryption *StorageEncryption `json:"storageEncryption,omitempty"`
}

// VaultAuthStatus defines the observed state of VaultAuth
type VaultAuthStatus struct {
	// Valid auth mechanism.
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultAuth is the Schema for the vaultauths API
type VaultAuth struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultAuthSpec   `json:"spec,omitempty"`
	Status VaultAuthStatus `json:"status,omitempty"`
}

// StorageEncryption provides the necessary configuration need to encrypt the storage cache
// entries using Vault's Transit engine. It only supports Kubernetes Auth for now.
type StorageEncryption struct {
	// Mount path of the Transit engine in Vault.
	Mount string `json:"mount"`
	// KeyName to use for encrypt/decrypt operations via Vault Transit.
	KeyName string `json:"keyName"`
}

//+kubebuilder:object:root=true

// VaultAuthList contains a list of VaultAuth
type VaultAuthList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultAuth `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultAuth{}, &VaultAuthList{})
}
