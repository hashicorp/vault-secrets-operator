// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultConnectionSpec defines the desired state of VaultConnection
type VaultConnectionSpec struct {
	// Address of the Vault server
	Address string `json:"address"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
	// TLSServerName to use as the SNI host for TLS connections.
	TLSServerName string `json:"tlsServerName,omitempty"`
	// CACertSecretRef is the name of a Kubernetes secret containing the trusted PEM encoded CA certificate chain as `ca.crt`.
	CACertSecretRef string `json:"caCertSecretRef,omitempty"`
	// SkipTLSVerify for TLS connections.
	// +kubebuilder:default=false
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
}

// VaultConnectionStatus defines the observed state of VaultConnection
type VaultConnectionStatus struct {
	// Valid auth mechanism.
	Valid bool `json:"valid"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultConnection is the Schema for the vaultconnections API
type VaultConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultConnectionSpec   `json:"spec,omitempty"`
	Status VaultConnectionStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultConnectionList contains a list of VaultConnection
type VaultConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultConnection{}, &VaultConnectionList{})
}
