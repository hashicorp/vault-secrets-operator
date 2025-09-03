// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultTokenSecretSpec defines the desired state of VaultTokenSecret.
type VaultTokenSecretSpec struct {
	// VaultAuthRef to the VaultAuth resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultAuthRefB`. If no namespace prefix is provided it will default to the
	// namespace of the VaultAuth CR. If no value is specified for VaultAuthRef the Operator will
	// default to the `default` VaultAuth, configured in the operator's namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace of the secrets engine mount in Vault. If not set, the namespace that's
	// part of VaultAuth resource will be inferred.
	Namespace string `json:"namespace,omitempty"`
	// Mount for the secret in Vault
	// RefreshAfter a period of time, in duration notation e.g. 30s, 1m, 24h
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(\.[0-9]+)?(s|m|h))$`
	RefreshAfter string `json:"refreshAfter,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// All configured targets will be ignored if HMACSecretData is set to false.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination provides configuration necessary for syncing the Vault secret to Kubernetes.
	Destination Destination `json:"destination"`

	// TokenRole is the name of the token role to use when creating the token.
	TokenRole string `json:"tokenRole,omitempty"`

	TTL               string            `json:"ttl,omitempty"`
	Policies          []string          `json:"policies,omitempty"`
	No_default_policy bool              `json:"noDefaultPolicy,omitempty"`
	DisplayName       string            `json:"displayName,omitempty"`
	EntityAlias       string            `json:"entityAlias,omitempty"`
	Meta              map[string]string `json:"meta,omitempty"`

	// RenewalPercent is the percent out of 100 of the lease duration when the
	// lease is renewed. Defaults to 67 percent plus jitter.
	// +kubebuilder:default=67
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=90
	RenewalPercent int `json:"renewalPercent,omitempty"`
	// Revoke the existing lease on VDS resource deletion.
	Revoke bool `json:"revoke,omitempty"`
}

// VaultTokenSecretStatus defines the observed state of VaultTokenSecret.
type VaultTokenSecretStatus struct {
	// LastGeneration is the Generation of the last reconciled resource.
	LastGeneration int64 `json:"lastGeneration"`
	// TokenAccessor is the accessor of the token created by the operator.
	// This is used to revoke the token when the resource is deleted.
	TokenAccessor   string          `json:"tokenAccessor,omitempty"`
	EntityID        string          `json:"entity_id,omitempty"`
	LeaseDuration   int             `json:"lease_duration,omitempty"`
	LastRenewalTime int64           `json:"lastRenewalTime"`
	VaultClientMeta VaultClientMeta `json:"vaultClientMeta,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// VaultTokenSecret is the Schema for the vaulttokensecrets API.
type VaultTokenSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultTokenSecretSpec   `json:"spec,omitempty"`
	Status VaultTokenSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultTokenSecretList contains a list of VaultTokenSecret.
type VaultTokenSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultTokenSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultTokenSecret{}, &VaultTokenSecretList{})
}
