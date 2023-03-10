// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RolloutRestartTarget struct {
	// +kubebuilder:validation:Enum={Deployment,DaemonSet,StatefulSet}
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// VaultDynamicSecretSpec defines the desired state of VaultDynamicSecret
type VaultDynamicSecretSpec struct {
	// VaultAuthRef to the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`
	// Namespace where the secrets engine is mounted in Vault.
	Namespace string `json:"namespace,omitempty"`
	// Mount path of the secret's engine in Vault.
	Mount string `json:"mount"`
	// Role in Vault to get the credentials for.
	Role string `json:"role"`
	// Dest could be some sort of k8s secret or something like that ....
	Dest string `json:"dest"`
	// RolloutRestartTargets
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
}

// VaultDynamicSecretStatus defines the observed state of VaultDynamicSecret
type VaultDynamicSecretStatus struct {
	// LastRenewalTime of the last, successful, secret lease renewal,
	LastRenewalTime int64 `json:"lastRenewalTime"`
	// SecretLease for the Vault secret.
	SecretLease VaultSecretLease `json:"secretLease"`
	// LastRuntimePodName
	LastRuntimePodName string `json:"LastRuntimePodName,omitempty"`
}

// VaultTokenMeta describes the Vault token used to sync the secret
type VaultTokenMeta struct {
	Accessor      string `json:"accessor"`
	EntityID      string `json:"entityID"`
	LeaseDuration int    `json:"leaseDuration"`
	Renewable     bool   `json:"renewable"`
}

type VaultSecretLease struct {
	// ID of the Vault secret.
	ID string `json:"id"`
	// LeaseDuration of the Vault secret.
	LeaseDuration int `json:"duration"`
	// Renewable Vault secret lease
	Renewable bool `json:"renewable"`
	// RequestID of the Vault secret request.
	RequestID string `json:"requestID"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultDynamicSecret is the Schema for the vaultdynamicsecrets API
type VaultDynamicSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultDynamicSecretSpec   `json:"spec,omitempty"`
	Status VaultDynamicSecretStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultDynamicSecretList contains a list of VaultDynamicSecret
type VaultDynamicSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultDynamicSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultDynamicSecret{}, &VaultDynamicSecretList{})
}
