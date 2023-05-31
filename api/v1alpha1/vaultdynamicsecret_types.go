// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

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
	// RequestHTTPMethod to use when syncing Secrets from Vault.
	// Setting a value here is not typically required.
	// If left unset the Operator will make requests using the GET method.
	// In the case where Params are specified the Operator will use the PUT method.
	// Please consult https://developer.hashicorp.com/vault/docs/secrets if you are
	// uncertain about what method to use.
	// Of note, the Vault client treats PUT and POST as being equivalent.
	// The underlying Vault client implementation will always use the PUT method.
	// +kubebuilder:validation:Enum={GET,POST,PUT}
	RequestHTTPMethod string `json:"requestHTTPMethod,omitempty"`
	// Path in Vault to get the credentials for, and is relative to Mount.
	// Please consult https://developer.hashicorp.com/vault/docs/secrets if you are
	// uncertain about what 'path' should be set to.
	Path string `json:"path"`
	// Params that can be passed when requesting credentials/secrets.
	// When Params is set the configured RequestHTTPMethod will be
	// ignored. See RequestHTTPMethod for more details.
	// Please consult https://developer.hashicorp.com/vault/docs/secrets if you are
	// uncertain about what 'params' should/can be set to.
	Params map[string]string `json:"params,omitempty"`
	// RenewalPercent is the percent out of 100 of the lease duration when the
	// lease is renewed. Defaults to 67 percent plus jitter.
	// +kubebuilder:default=67
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=90
	RenewalPercent int `json:"renewalPercent,omitempty"`
	// Revoke the existing lease on VDS resource deletion.
	Revoke bool `json:"revoke,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination provides configuration necessary for syncing the Vault secret to Kubernetes.
	Destination Destination `json:"destination"`
}

// VaultDynamicSecretStatus defines the observed state of VaultDynamicSecret
type VaultDynamicSecretStatus struct {
	// LastRenewalTime of the last successful secret lease renewal.
	LastRenewalTime int64 `json:"lastRenewalTime"`
	// LastGeneration is the Generation of the last reconciled resource.
	LastGeneration int64 `json:"lastGeneration"`
	// SecretLease for the Vault secret.
	SecretLease VaultSecretLease `json:"secretLease"`
	// LastRuntimePodUID used for tracking the transition from one Pod to the next.
	// It is used to mitigate the effects of a Vault lease renewal storm.
	LastRuntimePodUID types.UID `json:"lastRuntimePodUID,omitempty"`
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

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

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
