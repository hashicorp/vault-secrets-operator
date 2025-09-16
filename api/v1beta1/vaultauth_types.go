// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultAuthConfigKubernetes provides VaultAuth configuration options needed for authenticating to Vault.
type VaultAuthConfigKubernetes struct {
	// Role to use for authenticating to Vault.
	Role string `json:"role,omitempty"`
	// ServiceAccount to use when authenticating to Vault's
	// authentication backend. This must reside in the consuming secret's (VDS/VSS/PKI) namespace.
	ServiceAccount string `json:"serviceAccount,omitempty"`
	// TokenAudiences to include in the ServiceAccount token.
	TokenAudiences []string `json:"audiences,omitempty"`
	// TokenExpirationSeconds to set the ServiceAccount token.
	// +kubebuilder:default=600
	// +kubebuilder:validation:Minimum=600
	TokenExpirationSeconds int64 `json:"tokenExpirationSeconds,omitempty"`
}

// Merge merges the other VaultAuthConfigKubernetes into a copy of the current.
// If the current value is empty, it will be replaced by the other value. If the
// merger is successful, the copy is returned.
func (a *VaultAuthConfigKubernetes) Merge(other *VaultAuthConfigKubernetes) (*VaultAuthConfigKubernetes, error) {
	c := a.DeepCopy()
	if c.Role == "" {
		c.Role = other.Role
	}
	if c.ServiceAccount == "" {
		c.ServiceAccount = other.ServiceAccount
	}
	if len(c.TokenAudiences) == 0 {
		c.TokenAudiences = other.TokenAudiences
	}
	if c.TokenExpirationSeconds == 0 {
		c.TokenExpirationSeconds = other.TokenExpirationSeconds
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks that the VaultAuthConfigKubernetes is valid. All validation
// errors are returned.
func (a *VaultAuthConfigKubernetes) Validate() error {
	var errs error
	if a.Role == "" {
		errs = errors.Join(fmt.Errorf("empty role"))
	}

	if a.ServiceAccount == "" {
		errs = errors.Join(fmt.Errorf("empty serviceAccount"))
	}

	return errs
}

// VaultAuthConfigJWT provides VaultAuth configuration options needed for authenticating to Vault.
type VaultAuthConfigJWT struct {
	// Role to use for authenticating to Vault.
	Role string `json:"role,omitempty"`
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

// Merge merges the other VaultAuthConfigJWT into a copy of the current. If the
// current value is empty, it will be replaced by the other value. If the merger
// is successful, the copy is returned.
func (a *VaultAuthConfigJWT) Merge(other *VaultAuthConfigJWT) (*VaultAuthConfigJWT, error) {
	c := a.DeepCopy()
	if c.Role == "" {
		c.Role = other.Role
	}
	if c.SecretRef == "" {
		c.SecretRef = other.SecretRef
	}
	if c.ServiceAccount == "" {
		c.ServiceAccount = other.ServiceAccount
	}
	if len(c.TokenAudiences) == 0 {
		c.TokenAudiences = other.TokenAudiences
	}
	if c.TokenExpirationSeconds == 0 {
		c.TokenExpirationSeconds = other.TokenExpirationSeconds
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks that the VaultAuthConfigJWT is valid. All validation errors
// are returned.
func (a *VaultAuthConfigJWT) Validate() error {
	var errs error
	if a.Role == "" {
		errs = errors.Join(fmt.Errorf("empty role"))
	}

	return errs
}

// VaultAuthConfigAppRole provides VaultAuth configuration options needed for authenticating to
// Vault via an AppRole AuthMethod.
type VaultAuthConfigAppRole struct {
	// RoleID of the AppRole Role to use for authenticating to Vault.
	RoleID string `json:"roleId,omitempty"`

	// SecretRef is the name of a Kubernetes secret in the consumer's (VDS/VSS/PKI) namespace which
	// provides the AppRole Role's SecretID. The secret must have a key named `id` which holds the
	// AppRole Role's secretID.
	SecretRef string `json:"secretRef,omitempty"`
}

// Merge merges the other VaultAuthConfigAppRole into a copy of the current. If
// the current value is empty, it will be replaced by the other value. If the
// merger is successful, the copy is returned.
func (a *VaultAuthConfigAppRole) Merge(other *VaultAuthConfigAppRole) (*VaultAuthConfigAppRole, error) {
	c := a.DeepCopy()
	if c.RoleID == "" {
		c.RoleID = other.RoleID
	}
	if c.SecretRef == "" {
		c.SecretRef = other.SecretRef
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks that the VaultAuthConfigAppRole is valid. All validation
// errors are returned.
func (a *VaultAuthConfigAppRole) Validate() error {
	var errs error
	if a.RoleID == "" {
		errs = errors.Join(fmt.Errorf("empty roleID"))
	}

	if a.SecretRef == "" {
		errs = errors.Join(fmt.Errorf("empty secretRef"))
	}

	return errs
}

// VaultAuthConfigAWS provides VaultAuth configuration options needed for
// authenticating to Vault via an AWS AuthMethod. Will use creds from
// `SecretRef` or `IRSAServiceAccount` if provided, in that order. If neither
// are provided, the underlying node role or instance profile will be used to
// authenticate to Vault.
type VaultAuthConfigAWS struct {
	// Vault role to use for authenticating
	Role string `json:"role,omitempty"`
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

	// SecretRef is the name of a Kubernetes Secret in the consumer's (VDS/VSS/PKI) namespace
	// which holds credentials for AWS. Expected keys include `access_key_id`, `secret_access_key`,
	// `session_token`
	SecretRef string `json:"secretRef,omitempty"`

	// IRSAServiceAccount name to use with IAM Roles for Service Accounts
	// (IRSA), and should be annotated with "eks.amazonaws.com/role-arn". This
	// ServiceAccount will be checked for other EKS annotations:
	// eks.amazonaws.com/audience and eks.amazonaws.com/token-expiration
	IRSAServiceAccount string `json:"irsaServiceAccount,omitempty"`
}

// Merge merges the other VaultAuthConfigAWS into a copy of the current. If the
// current value is empty, it will be replaced by the other value. If the merger
// is successful, the copy is returned.
func (a *VaultAuthConfigAWS) Merge(other *VaultAuthConfigAWS) (*VaultAuthConfigAWS, error) {
	c := a.DeepCopy()
	if c.Role == "" {
		c.Role = other.Role
	}
	if c.Region == "" {
		c.Region = other.Region
	}
	if c.HeaderValue == "" {
		c.HeaderValue = other.HeaderValue
	}
	if c.SessionName == "" {
		c.SessionName = other.SessionName
	}
	if c.STSEndpoint == "" {
		c.STSEndpoint = other.STSEndpoint
	}
	if c.IAMEndpoint == "" {
		c.IAMEndpoint = other.IAMEndpoint
	}
	if c.SecretRef == "" {
		c.SecretRef = other.SecretRef
	}
	if c.IRSAServiceAccount == "" {
		c.IRSAServiceAccount = other.IRSAServiceAccount
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks that the VaultAuthConfigAWS is valid. All validation errors
// are returned.
func (a *VaultAuthConfigAWS) Validate() error {
	var errs error
	if a.Role == "" {
		errs = errors.Join(fmt.Errorf("empty role"))
	}

	return errs
}

// VaultAuthConfigGCP provides VaultAuth configuration options needed for
// authenticating to Vault via a GCP AuthMethod, using workload identity
type VaultAuthConfigGCP struct {
	// Vault role to use for authenticating
	Role string `json:"role,omitempty"`

	// WorkloadIdentityServiceAccount is the name of a Kubernetes service
	// account (in the same Kubernetes namespace as the Vault*Secret referencing
	// this resource) which has been configured for workload identity in GKE.
	// Should be annotated with "iam.gke.io/gcp-service-account".
	WorkloadIdentityServiceAccount string `json:"workloadIdentityServiceAccount,omitempty"`

	// GCP Region of the GKE cluster's identity provider. Defaults to the region
	// returned from the operator pod's local metadata server.
	Region string `json:"region,omitempty"`

	// GKE cluster name. Defaults to the cluster-name returned from the operator
	// pod's local metadata server.
	ClusterName string `json:"clusterName,omitempty"`

	// GCP project ID. Defaults to the project-id returned from the operator
	// pod's local metadata server.
	ProjectID string `json:"projectID,omitempty"`
}

// Merge merges the other VaultAuthConfigGCP into a copy of the current. If the
// current value is empty, it will be replaced by the other value. If the merger
// is successful, the copy is returned.
func (a *VaultAuthConfigGCP) Merge(other *VaultAuthConfigGCP) (*VaultAuthConfigGCP, error) {
	c := a.DeepCopy()
	if c.Role == "" {
		c.Role = other.Role
	}
	if c.WorkloadIdentityServiceAccount == "" {
		c.WorkloadIdentityServiceAccount = other.WorkloadIdentityServiceAccount
	}
	if c.Region == "" {
		c.Region = other.Region
	}
	if c.ClusterName == "" {
		c.ClusterName = other.ClusterName
	}
	if c.ProjectID == "" {
		c.ProjectID = other.ProjectID
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks that the VaultAuthConfigGCP is valid. All validation errors
// are returned.
func (a *VaultAuthConfigGCP) Validate() error {
	var errs error
	if a.Role == "" {
		errs = errors.Join(fmt.Errorf("empty role"))
	}
	if a.WorkloadIdentityServiceAccount == "" {
		errs = errors.Join(fmt.Errorf("empty workloadIdentityServiceAccount"))
	}

	return errs
}

// VaultAuthGlobalRef is a reference to a VaultAuthGlobal resource. A referring
// VaultAuth resource can use the VaultAuthGlobal resource to share common
// configuration across multiple VaultAuth resources. The VaultAuthGlobal
// resource is used to store global configuration for VaultAuth resources.
type VaultAuthGlobalRef struct {
	// Name of the VaultAuthGlobal resource.
	// +kubebuilder:validation:Pattern=`^([a-z0-9.-]{1,253})$`
	Name string `json:"name,omitempty"`
	// Namespace of the VaultAuthGlobal resource. If not provided, the namespace of
	// the referring VaultAuth resource is used.
	// +kubebuilder:validation:Pattern=`^([a-z0-9-]{1,63})$`
	Namespace string `json:"namespace,omitempty"`
	// MergeStrategy configures the merge strategy for HTTP headers and parameters
	// that are included in all Vault authentication requests.
	MergeStrategy *MergeStrategy `json:"mergeStrategy,omitempty"`
	// AllowDefault when set to true will use the default VaultAuthGlobal resource
	// as the default if Name is not set. The 'allow-default-globals' option must be
	// set on the operator's '-global-vault-auth-options' flag
	//
	// The default VaultAuthGlobal search is conditional.
	// When a ref Namespace is set, the search for the default
	// VaultAuthGlobal resource is constrained to that namespace.
	// Otherwise, the search order is:
	// 1. The default VaultAuthGlobal resource in the referring VaultAuth resource's
	// namespace.
	// 2. The default VaultAuthGlobal resource in the Operator's namespace.
	AllowDefault *bool `json:"allowDefault,omitempty"`
}

// MergeStrategy provides the configuration for merging HTTP headers and
// parameters from the referring VaultAuth resource and its VaultAuthGlobal
// resource.
type MergeStrategy struct {
	// Headers configures the merge strategy for HTTP headers that are included in
	// all Vault requests. Choices are `union`, `replace`, or `none`.
	//
	// If `union` is set, the headers from the VaultAuthGlobal and VaultAuth
	// resources are merged. The headers from the VaultAuth always take precedence.
	//
	// If `replace` is set, the first set of non-empty headers taken in order from:
	// VaultAuth, VaultAuthGlobal auth method, VaultGlobal default headers.
	//
	// If `none` is set, the headers from the
	// VaultAuthGlobal resource are ignored and only the headers from the VaultAuth
	// resource are used. The default is `none`.
	// +kubebuilder:validation:Enum=union;replace;none
	Headers string `json:"headers,omitempty"`
	// Params configures the merge strategy for HTTP parameters that are included in
	// all Vault requests. Choices are `union`, `replace`, or `none`.
	//
	// If `union` is set, the parameters from the VaultAuthGlobal and VaultAuth
	// resources are merged. The parameters from the VaultAuth always take
	// precedence.
	//
	// If `replace` is set, the first set of non-empty parameters taken in order from:
	// VaultAuth, VaultAuthGlobal auth method, VaultGlobal default parameters.
	//
	// If `none` is set, the parameters from the VaultAuthGlobal resource are ignored
	// and only the parameters from the VaultAuth resource are used. The default is
	// `none`.
	// +kubebuilder:validation:Enum=union;replace;none
	Params string `json:"params,omitempty"`
}

// VaultAuthSpec defines the desired state of VaultAuth
type VaultAuthSpec struct {
	// VaultConnectionRef to the VaultConnection resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultConnectionRefB`. If no namespace prefix is provided it will default to
	// the namespace of the VaultConnection CR. If no value is specified for VaultConnectionRef the
	// Operator will default to the `default` VaultConnection, configured in the operator's namespace.
	VaultConnectionRef string `json:"vaultConnectionRef,omitempty"`
	// VaultAuthGlobalRef.
	VaultAuthGlobalRef *VaultAuthGlobalRef `json:"vaultAuthGlobalRef,omitempty"`
	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`
	// AllowedNamespaces Kubernetes Namespaces which are allow-listed for use with this AuthMethod.
	// This field allows administrators to customize which Kubernetes namespaces are authorized to
	// use with this AuthMethod. While Vault will still enforce its own rules, this has the added
	// configurability of restricting which VaultAuthMethods can be used by which namespaces.
	// Accepted values:
	// []{"*"} - wildcard, all namespaces.
	// []{"a", "b"} - list of namespaces.
	// unset - disallow all namespaces except the Operator's the VaultAuthMethod's namespace, this
	// is the default behavior.
	AllowedNamespaces []string `json:"allowedNamespaces,omitempty"`
	// Method to use when authenticating to Vault.
	// +kubebuilder:validation:Enum=kubernetes;jwt;appRole;aws;gcp
	Method string `json:"method,omitempty"`
	// Mount to use when authenticating to auth method.
	Mount string `json:"mount,omitempty"`
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
	// GCP specific auth configuration, requires that Method be set to `gcp`.
	GCP *VaultAuthConfigGCP `json:"gcp,omitempty"`
	// StorageEncryption provides the necessary configuration to encrypt the client storage cache.
	// This should only be configured when client cache persistence with encryption is enabled.
	// This is done by passing setting the manager's commandline argument
	// --client-cache-persistence-model=direct-encrypted. Typically, there should only ever
	// be one VaultAuth configured with StorageEncryption in the Cluster, and it should have
	// the label: cacheStorageEncryption=true
	StorageEncryption *StorageEncryption `json:"storageEncryption,omitempty"`
}

// VaultAuthStatus defines the observed state of VaultAuth
type VaultAuthStatus struct {
	// Valid auth mechanism.
	Valid *bool `json:"valid,omitempty"`
	// Error is a human-readable error message indicating why the VaultAuth is invalid.
	Error string `json:"error,omitempty"`
	// Conditions hold information that can be used by other apps to determine the
	// health of the resource instance.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// SpecHash is a SHA256 hash of the spec, used to determine if the spec has changed.
	SpecHash string `json:"specHash,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VaultAuth is the Schema for the vaultauths API
type VaultAuth struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultAuthSpec   `json:"spec,omitempty"`
	Status VaultAuthStatus `json:"status,omitempty"`
}

// StorageEncryption provides the necessary configuration need to encrypt the storage cache
// entries using Vault's Transit engine.
type StorageEncryption struct {
	// Mount path of the Transit engine in Vault.
	Mount string `json:"mount"`
	// KeyName to use for encrypt/decrypt operations via Vault Transit.
	KeyName string `json:"keyName"`
}

type VaultAuthRef struct {
	// Name of the VaultAuth resource.
	Name string `json:"name"`
	// Namespace of the VaultAuth resource.
	Namespace string `json:"namespace,omitempty"`
	// TrustNamespace of the referring VaultAuth resource. This means that any Vault
	// credentials will be provided by resources in the same namespace as the
	// VaultAuth resource. Otherwise, the credentials will be provided by the secret
	// resource's namespace.
	TrustNamespace bool `json:"trustNamespace,omitempty"`
}

// +kubebuilder:object:root=true

// VaultAuthList contains a list of VaultAuth
type VaultAuthList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultAuth `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultAuth{}, &VaultAuthList{})
}
