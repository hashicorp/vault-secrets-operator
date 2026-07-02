// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HCPAuthSpec defines the desired state of HCPAuth
type HCPAuthSpec struct {
	// OrganizationID of the HCP organization.
	OrganizationID string `json:"organizationID"`
	// ProjectID of the HCP project.
	ProjectID string `json:"projectID"`
	// AllowedNamespaces Kubernetes Namespaces which are allow-listed for use with this AuthMethod.
	// This field allows administrators to customize which Kubernetes namespaces are authorized to
	// use with this AuthMethod. While Vault will still enforce its own rules, this has the added
	// configurability of restricting which HCPAuthMethods can be used by which namespaces.
	// Accepted values:
	// []{"*"} - wildcard, all namespaces.
	// []{"a", "b"} - list of namespaces.
	// unset - disallow all namespaces except the Operator's the HCPAuthMethod's namespace, this
	// is the default behavior.
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`
	// Method to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=servicePrincipal
	// +kubebuilder:default="servicePrincipal"
	Method string `json:"method,omitempty"`
	// ServicePrincipal provides the necessary configuration for authenticating to
	// HCP using a service principal. For security reasons, only project-level
	// service principals should ever be used.
	ServicePrincipal *HCPAuthServicePrincipal `json:"servicePrincipal,omitempty"`
}

// HCPAuthServicePrincipal provides HCPAuth configuration options needed for
// authenticating to HCP using a service principal configured in SecretRef.
type HCPAuthServicePrincipal struct {
	// SecretRef is the name of a Kubernetes secret in the consumer's
	// (VDS/VSS/PKI/HCP) namespace which provides the HCP ServicePrincipal clientID,
	// and clientSecret.
	// The secret data must have the following structure {
	//   "clientID": "clientID",
	//   "clientSecret": "clientSecret",
	// }
	SecretRef string `json:"secretRef"`
}

// HCPAuthStatus defines the observed state of HCPAuth
type HCPAuthStatus struct {
	// Valid auth mechanism.
	Valid *bool  `json:"valid"`
	Error string `json:"error"`
	// Conditions hold information that can be used by other apps to determine the
	// health of the resource instance.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// HCPAuth is the Schema for the hcpauths API
type HCPAuth struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HCPAuthSpec   `json:"spec,omitempty"`
	Status HCPAuthStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HCPAuthList contains a list of HCPAuth
type HCPAuthList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HCPAuth `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HCPAuth{}, &HCPAuthList{})
}
