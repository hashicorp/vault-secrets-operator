// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultConnectionSpec defines the desired state of VaultConnection
type VaultConnectionSpec struct {
	// Address of the Vault server
	Address string `json:"address"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
	// TLSServerName to use as the SNI host for TLS connections.
	TLSServerName string `json:"tlsServerName,omitempty"`
	// CACertSecretRef is the name of a Kubernetes secret containing the trusted PEM encoded CA certificate chain as `ca.crt`.
	// CACertPath and CACertSecretRef are mutually exclusive, and only one should be specified.
	CACertSecretRef string `json:"caCertSecretRef,omitempty"`
	// CACertPath is the path to a trusted PEM-encoded CA certificate file on the filesystem that can be used to validate
	// the certificate presented by the Vault server.
	// CACertPath and CACertSecretRef are mutually exclusive, and only one should be specified.
	CACertPath string `json:"caCertPath,omitempty"`
	// SkipTLSVerify for TLS connections.
	// +kubebuilder:default=false
	SkipTLSVerify bool `json:"skipTLSVerify"`
	// Timeout applied to all Vault requests for this connection. If not set, the
	// default timeout from the Vault API client config is used.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(s|m|h))$`
	Timeout string `json:"timeout,omitempty"`
}

// VaultConnectionStatus defines the observed state of VaultConnection
type VaultConnectionStatus struct {
	// Valid auth mechanism.
	Valid *bool `json:"valid"`
	// Conditions hold information that can be used by other apps to determine the
	// health of the resource instance.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VaultConnection is the Schema for the vaultconnections API
// +kubebuilder:printcolumn:name="Healthy",type="string",JSONPath=`.status.conditions[?(@.type == "Healthy")].status`,description="health status"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type == "Ready")].status`,description="resource ready"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`,description="resource age"
type VaultConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultConnectionSpec   `json:"spec,omitempty"`
	Status VaultConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultConnectionList contains a list of VaultConnection
type VaultConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultConnection{}, &VaultConnectionList{})
}
