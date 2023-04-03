// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultKubernetesAuthBackendRoleSpec VaultAuthBackendSpec VaultAuthSpec defines the desired state of VaultKubernetesAuthBackendRoleSpec
type VaultKubernetesAuthBackendRoleSpec struct {
	// VaultAuthRef of the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`

	// Namespace to auth to in Vault
	Namespace string `json:"namespace,omitempty"`

	// Mount to use when authenticating to auth method.
	// +kubebuilder:validation:Required
	Path string `json:"path"`

	// Name of the role.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// BoundServiceAccountNames is a list of service account names able to access this role. If set to "*" all names are allowed.
	// +kubebuilder:validation:Required
	BoundServiceAccountNames []string `json:"boundServiceAccountNames"`

	// BoundServiceAccountNamespaces is a list of namespaces allowed to access this role. If set to "*" all namespaces are allowed.
	// +kubebuilder:validation:Required
	BoundServiceAccountNamespaces []string `json:"boundServiceAccountNamespaces"`

	// AliasNameSource Configures how identity aliases are generated.
	// Valid choices are: serviceaccount_uid, serviceaccount_name.
	// When serviceaccount_uid is specified, the machine generated UID from the service account will be used as the identity alias name.
	// When serviceaccount_name is specified, the service account's namespace and name will be used as the identity alias name e.g. vault/vault-auth.
	// While it is strongly advised that you use serviceaccount_uid, you may also use serviceaccount_name in cases where you want to set the alias ahead of time, and the risks are mitigated or otherwise acceptable given your use case.
	// It is very important to limit who is able to delete/create service accounts within a given cluster.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="serviceaccount_uid"
	// +kubebuilder:validation:Enum={serviceaccount_uid,serviceaccount_name}
	AliasNameSource string `json:"aliasNameSource,omitempty"`

	// Audience claim to verify in the JWT (Optional).
	// +kubebuilder:validation:Optional
	Audience string `json:"audience,omitempty"`

	// TokenTTL is the incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
	// +kubebuilder:validation:Optional
	TokenTTL string `json:"tokenTTL,omitempty"`

	// TokenMaxTTL is the maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
	// +kubebuilder:validation:Optional
	TokenMaxTTL string `json:"tokenMaxTTL,omitempty"`

	// Policies is a list of policies to encode onto generated tokens.
	// +kubebuilder:validation:Optional
	Policies []string `json:"tokenPolicies,omitempty"`

	// Policies is a list of policies to encode onto generated tokens.
	// +kubebuilder:validation:Optional
	TokenBoundCIDRs []string `json:"tokenBoundCIDRs,omitempty"`

	// TokenExplicitMaxTTL if set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.
	// +kubebuilder:validation:Optional
	TokenExplicitMaxTTL string `json:"tokenExplicitMaxTTL,omitempty"`

	// TokenNoDefaultPolicy if set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.
	// +kubebuilder:validation:Optional
	TokenNoDefaultPolicy bool `json:"tokenNoDefaultPolicy,omitempty"`

	// TokenNumUses is the maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create child tokens, you will need to set this value to 0.
	// +kubebuilder:validation:Optional
	TokenNumUses int `json:"tokenNumUses,omitempty"`

	// TokenPeriod is the period, if any, to set on the token.
	// +kubebuilder:validation:Optional
	TokenPeriod string `json:"tokenPeriod,omitempty"`

	// TokenType is the type of token that should be generated. Can be service, batch, or default to use the mount's tuned default (which unless changed will be service tokens). For token store roles, there are two additional possibilities: default-service and default-batch which specify the type to return unless the client requests a different type at generation time.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum={service,batch,default}
	TokenType string `json:"tokenType,omitempty"`
}

// VaultKubernetesAuthBackendRoleStatus defines the observed state of VaultKubernetesAuthBackendRoleSpec
type VaultKubernetesAuthBackendRoleStatus struct {
	// Valid auth mechanism.
	Valid bool   `json:"valid"`
	Error string `json:"error"`
	Path  string `json:"path"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultKubernetesAuthBackendRole is the Schema for the vaultkubernetesauthbackendroles API
type VaultKubernetesAuthBackendRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultKubernetesAuthBackendRoleSpec   `json:"spec,omitempty"`
	Status VaultKubernetesAuthBackendRoleStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultKubernetesAuthBackendRoleList contains a list of VaultKubernetesAuthBackendRole
type VaultKubernetesAuthBackendRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultKubernetesAuthBackendRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultKubernetesAuthBackendRole{}, &VaultKubernetesAuthBackendRoleList{})
}
