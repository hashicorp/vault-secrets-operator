// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultTransitSpec defines the desired state of VaultTransit
type VaultTransitSpec struct {
	// Key for encrypt/decrypt operations via Vault's Transit secrets engine.
	// TODO: rename to KeyName
	Key string `json:"key"`
	// VaultAuthRef to the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace where the secrets engine is mounted in Vault.
	Namespace string `json:"namespace,omitempty"`
	// Mount path of the secret's engine in Vault.
	Mount string `json:"mount"`
}

// VaultTransitStatus defines the observed state of VaultTransit
type VaultTransitStatus struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultTransit is the Schema for the vaulttransits API
type VaultTransit struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultTransitSpec   `json:"spec,omitempty"`
	Status VaultTransitStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultTransitList contains a list of VaultTransit
type VaultTransitList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultTransit `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultTransit{}, &VaultTransitList{})
}
