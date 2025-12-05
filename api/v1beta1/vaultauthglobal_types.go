// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultAuthGlobalSpec defines the desired state of VaultAuthGlobal
type VaultAuthGlobalSpec struct {
	// AllowedNamespaces Kubernetes Namespaces which are allow-listed for use with
	// this VaultAuthGlobal. This field allows administrators to customize which
	// Kubernetes namespaces are authorized to reference this resource. While Vault
	// will still enforce its own rules, this has the added configurability of
	// restricting which VaultAuthMethods can be used by which namespaces. Accepted
	// values: []{"*"} - wildcard, all namespaces. []{"a", "b"} - list of namespaces.
	// unset - disallow all namespaces except the Operator's and the referring
	// VaultAuthMethod's namespace, this is the default behavior.
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`
	// VaultConnectionRef to the VaultConnection resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultConnectionRefB`. If no namespace prefix is provided it will default to
	// the namespace of the VaultConnection CR. If no value is specified for VaultConnectionRef the
	// Operator will default to the `default` VaultConnection, configured in the operator's namespace.
	VaultConnectionRef string `json:"vaultConnectionRef,omitempty"`
	// DefaultVaultNamespace to auth to in Vault, if not specified the namespace of the auth
	// method will be used. This can be used as a default Vault namespace for all
	// auth methods.
	DefaultVaultNamespace string `json:"defaultVaultNamespace,omitempty"`
	// DefaultAuthMethod to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=kubernetes;jwt;appRole;aws;gcp
	DefaultAuthMethod string `json:"defaultAuthMethod,omitempty"`
	// DefaultMount to use when authenticating to auth method. If not specified the mount of
	// the auth method configured in Vault will be used.
	DefaultMount string `json:"defaultMount,omitempty"`
	// DefaultParams to use when authenticating to Vault
	DefaultParams map[string]string `json:"params,omitempty"`
	// DefaultHeaders to be included in all Vault requests.
	DefaultHeaders map[string]string `json:"headers,omitempty"`
	// Kubernetes specific auth configuration, requires that the Method be set to `kubernetes`.
	Kubernetes *VaultAuthGlobalConfigKubernetes `json:"kubernetes,omitempty"`
	// AppRole specific auth configuration, requires that the Method be set to `appRole`.
	AppRole *VaultAuthGlobalConfigAppRole `json:"appRole,omitempty"`
	// JWT specific auth configuration, requires that the Method be set to `jwt`.
	JWT *VaultAuthGlobalConfigJWT `json:"jwt,omitempty"`
	// AWS specific auth configuration, requires that Method be set to `aws`.
	AWS *VaultAuthGlobalConfigAWS `json:"aws,omitempty"`
	// GCP specific auth configuration, requires that Method be set to `gcp`.
	GCP *VaultAuthGlobalConfigGCP `json:"gcp,omitempty"`
}

// VaultAuthGlobalStatus defines the observed state of VaultAuthGlobal
type VaultAuthGlobalStatus struct {
	// Valid auth mechanism.
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultAuthGlobal is the Schema for the vaultauthglobals API
type VaultAuthGlobal struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultAuthGlobalSpec   `json:"spec,omitempty"`
	Status VaultAuthGlobalStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultAuthGlobalList contains a list of VaultAuthGlobal
type VaultAuthGlobalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultAuthGlobal `json:"items"`
}

type VaultAuthGlobalConfigKubernetes struct {
	VaultAuthConfigKubernetes `json:",inline"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
}

type VaultAuthGlobalConfigJWT struct {
	VaultAuthConfigJWT `json:",inline"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
}

type VaultAuthGlobalConfigAppRole struct {
	VaultAuthConfigAppRole `json:",inline"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
}

type VaultAuthGlobalConfigAWS struct {
	VaultAuthConfigAWS `json:",inline"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
}

type VaultAuthGlobalConfigGCP struct {
	VaultAuthConfigGCP `json:",inline"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
}

func init() {
	SchemeBuilder.Register(&VaultAuthGlobal{}, &VaultAuthGlobalList{})
}
