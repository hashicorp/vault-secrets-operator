// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultKubernetesAuthBackendSpec defines the desired state of VaultKubernetesAuthBackendSpec
type VaultKubernetesAuthBackendSpec struct {
	// VaultAuthRef of the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`

	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`

	// Mount to use when authenticating to auth method.
	Path string `json:"path"`

	// KubernetesHost Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.
	// +kubebuilder:validation:Required
	// +kubebuilder:default="https://kubernetes.default.svc:443"
	KubernetesHost string `json:"kubernetesHost,omitempty"`

	// kubernetesCACert PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API. NOTE: Every line must end with a newline: \n
	// if omitted will default to the content of the file "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" in the operator pod
	// +kubebuilder:validation:Optional
	KubernetesCACert string `json:"kubernetesCaCert,omitempty"`

	// PEMKeys Optional list of PEM-formatted public keys or certificates used to verify the signatures of Kubernetes service account JWTs. If a certificate is given, its public key will be extracted. Not every installation of Kubernetes exposes these keys.
	// +kubebuilder:validation:Optional
	PEMKeys []string `json:"pemKeys,omitempty"`

	// Issuer Optional JWT issuer. If no issuer is specified, then this plugin will use kubernetes/serviceaccount as the default issuer. See these instructions for looking up the issuer for a given Kubernetes cluster.
	// +kubebuilder:validation:Optional
	Issuer string `json:"issuer,omitempty"`

	// DisableISSValidation Disable JWT issuer validation. Allows to skip ISS validation.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	DisableISSValidation bool `json:"disableIssValidation,omitempty"`

	// DisableLocalCAJWT Disable defaulting to the local CA cert and service account JWT when running in a Kubernetes pod.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	DisableLocalCAJWT bool `json:"disableLocalCaJwt,omitempty"`
}

// VaultKubernetesAuthBackendStatus defines the observed state of VaultKubernetesAuthBackendSpec
type VaultKubernetesAuthBackendStatus struct {
	// Valid auth mechanism.
	Valid bool   `json:"valid"`
	Error string `json:"error"`
	Path  string `json:"path"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultKubernetesAuthBackend is the Schema for the vaultkubernetesauthbackends API
type VaultKubernetesAuthBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultKubernetesAuthBackendSpec   `json:"spec,omitempty"`
	Status VaultKubernetesAuthBackendStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultKubernetesAuthBackendList contains a list of VaultKubernetesAuthBackend
type VaultKubernetesAuthBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultKubernetesAuthBackend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultKubernetesAuthBackend{}, &VaultKubernetesAuthBackendList{})
}
