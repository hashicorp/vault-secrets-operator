// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1beta1

import (
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

// VaultAuthConfigJWT provides VaultAuth configuration options needed for authenticating to Vault.
type VaultAuthConfigJWT struct {
	// Role to use for authenticating to Vault.
	Role string `json:"role"`
	// SecretRef is the name of a Kubernetes secret in the consumer's (VDS/VSS/PKI) namespace which
	// provides the JWT token to authenticate to Vault's JWT authentication backend. The secret must
	// have a key named `jwt` which holds the JWT token.
	SecretRef string `json:"secretRef,omitempty"`
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

// VaultAuthConfigAppRole provides VaultAuth configuration options needed for authenticating to
// Vault via an AppRole AuthMethod.
type VaultAuthConfigAppRole struct {
	// RoleID of the AppRole Role to use for authenticating to Vault.
	RoleID string `json:"roleId"`

	// SecretRef is the name of a Kubernetes secret in the consumer's (VDS/VSS/PKI) namespace which
	// provides the AppRole Role's SecretID. The secret must have a key named `id` which holds the
	// AppRole Role's secretID.
	SecretRef string `json:"secretRef"`
}

// VaultAuthConfigAWS provides VaultAuth configuration options needed for
// authenticating to Vault via an AWS AuthMethod. Will use creds from
// `SecretRef` or `IRSAServiceAccount` if provided, in that order. If neither
// are provided, the underlying node role or instance profile will be used to
// authenticate to Vault.
type VaultAuthConfigAWS struct {
	// Vault role to use for authenticating
	Role string `json:"role"`
	// AWS Region to use for signing the authentication request
	Region string `json:"region,omitempty"`
	// The Vault header value to include in the STS signing request
	HeaderValue string `json:"headerValue,omitempty"`

	// The role session name to use when creating a webidentity provider
	SessionName string `json:"sessionName,omitempty"`

	// The STS endpoint to use; if not set will use the default
	STSEndpoint string `json:"stsEndpoint,omitempty"`

	// The IAM endpoint to use; if not set will use the default
	IAMEndpoint string `json:"iamEndpoint,omitempty"`

	// SecretRef is the name of a Kubernetes Secret which holds credentials for
	// AWS. Expected keys include `access_key_id`, `secret_access_key`,
	// `session_token`
	SecretRef string `json:"secretRef,omitempty"`

	// IRSAServiceAccount name to use with IAM Roles for Service Accounts
	// (IRSA), and should be annotated with "eks.amazonaws.com/role-arn". This
	// ServiceAccount will be checked for other EKS annotations:
	// eks.amazonaws.com/audience and eks.amazonaws.com/token-expiration
	IRSAServiceAccount string `json:"irsaServiceAccount,omitempty"`
}

// VaultAuthSpec defines the desired state of VaultAuth
type VaultAuthSpec struct {
	// VaultConnectionRef of the corresponding VaultConnection CustomResource.
	// The connectionRef can be prefixed with a namespace, eg: `namespaceA/connectionB`.
	// If no namespace is specified the Operator will default to namespace of the VaultAuth CR.
	// If no value is specified the Operator will default to the `default` VaultConnection,
	// configured in its own Kubernetes namespace unless prefixed.
	VaultConnectionRef string `json:"vaultConnectionRef,omitempty"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// AllowedNamespaces Kubernetes Namespaces which are allow-listed for use with this AuthMethod.
	// This field allows administrators to customize which Kubernetes namespaces are authorized to
	// act with this AuthMethod. While Vault will still enforce its own rules, this has the added
	// configurability of restricting which AuthMethods can be used by which namespaces.
	// Accepted values:
	// []{"*"} - wildcard, all namespaces.
	// []{"a", "b"} - list of namespaces.
	// []{} - empty list, no namespaces.
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`
	// Method to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=kubernetes;jwt;appRole;aws
	Method string `json:"method"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount"`
	// Params to use when authenticating to Vault
	Params map[string]string `json:"params,omitempty"`
	// Headers to be included in all Vault requests.
	Headers map[string]string `json:"headers,omitempty"`
	// Kubernetes specific auth configuration, requires that the Method be set to `kubernetes`.
	Kubernetes *VaultAuthConfigKubernetes `json:"kubernetes,omitempty"`
	// AppRole specific auth configuration, requires that the Method be set to `appRole`.
	AppRole *VaultAuthConfigAppRole `json:"appRole,omitempty"`
	// JWT specific auth configuration, requires that the Method be set to `jwt`.
	JWT *VaultAuthConfigJWT `json:"jwt,omitempty"`
	// AWS specific auth configuration, requires that Method be set to `aws`.
	AWS *VaultAuthConfigAWS `json:"aws,omitempty"`
	// StorageEncryption provides the necessary configuration to encrypt the client storage cache.
	// This should only be configured when client cache persistence with encryption is enabled.
	// This is done by passing setting the manager's commandline argument
	// --client-cache-persistence-model=direct-encrypted. Typically there should only ever
	// be one VaultAuth configured with StorageEncryption in the Cluster, and it should have
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
