// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HCPAuthSpec defines the desired state of HCPAuth
type HCPAuthSpec struct {
	// OrganizationID
	OrganizationID string `json:"organizationID"`
	// ProjectID
	ProjectID string `json:"projectID"`
	// Method to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=servicePrincipal
	Method string `json:"method,omitempty"`
	// ServicePrincipal
	ServicePrincipal *HCPAuthServicePrincipal `json:"servicePrincipal,omitempty"`
}

// HCPAuthServicePrincipal provides HCPAuth configuration options needed for
// authenticating to HCP using a service principal configured in SecretRef.
type HCPAuthServicePrincipal struct {
	// SecretRef is the name of a Kubernetes secret in the consumer's (VDS/VSS/PKI/HCP) namespace which
	// provides the HCP ServicePrincipal clientID, and clientKey.
	// The secret data must have the following structure
	// {
	//   "clientID": "clientID",
	//   "clientKey": "clientKey",
	// }
	SecretRef string `json:"secretRef"`
}

// HCPAuthStatus defines the observed state of HCPAuth
type HCPAuthStatus struct {
	// Valid auth mechanism.
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// HCPAuth is the Schema for the hcpauths API
type HCPAuth struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HCPAuthSpec   `json:"spec,omitempty"`
	Status HCPAuthStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// HCPAuthList contains a list of HCPAuth
type HCPAuthList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HCPAuth `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HCPAuth{}, &HCPAuthList{})
}
