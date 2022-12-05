// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type VaultAuthAWS struct{}

type VaultAuthKubernetes struct{}

// VaultAuthSpec defines the desired state of VaultAuth
type VaultAuthSpec struct {
	// Address to the Vault server -- not sure if we want to support more than one?
	Address string `json:"address"`
	// Method to use when authenticating to Vault.
	Method string `json:"method"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
	// TLSServerName to use as the SNI host for TLS connections.
	TLSServerName string `json:"tlsServerName,omitempty"`
	// CACertFile containing the trusted PEM encoded CA certificate chain.
	CACertFile string `json:"caCertFile,omitempty"`
	// SkipTLSVerify for TLS connections.
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
	// SkipChildToken creation.
	// TODO: drop this as it probably only pertains to token auth
	SkipChildToken bool `json:"skipChildToken,omitempty"`
	// ChildTokenName to used when creating a child token.
	// TODO: drop this as it probably only pertains to token auth
	ChildTokenName string `json:"childTokenName"`
	// AllowedNamespaces, is the list of Kubernetes namespaces that are allowed to be serviced.
	// If none are provided all resources requesting this Auth will fail.
	// TODO: support globbing?
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`

	AWSAuth *VaultAuthAWS `json:"awsAuth"`
}

// VaultAuthStatus defines the observed state of VaultAuth
type VaultAuthStatus struct {
	// Valid auth mechanism.
	Valid bool `json:"valid"`
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
