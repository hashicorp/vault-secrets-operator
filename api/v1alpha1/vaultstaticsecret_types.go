// Copyright (c) 2022 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultStaticSecretSpec defines the desired state of VaultStaticSecret
type VaultStaticSecretSpec struct {
	// VaultAuthRef of the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace to get the secret from in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount for the secret in Vault
	Mount string `json:"mount"`
	// Name of the secret in Vault
	Name string `json:"name"`
	// Dest could be some sort of k8s secret or something like that ....
	Dest string `json:"dest"`
	// Secret type
	Type string `json:"type"`
	// RefreshAfter a period of time, in duration notation
	RefreshAfter string `json:"refreshAfter,omitempty"`
}

// VaultStaticSecretStatus defines the observed state of VaultStaticSecret
type VaultStaticSecretStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
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
