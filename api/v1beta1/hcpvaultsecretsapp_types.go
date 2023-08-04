// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HCPVaultSecretsAppSpec defines the desired state of HCPVaultSecretsApp
type HCPVaultSecretsAppSpec struct {
	// AppName
	AppName string `json:"appName"`
	// HCPAuthRef
	HCPAuthRef string `json:"hcpAuthRef,omitempty"`
	// RefreshAfter a period of time, in duration notation
	RefreshAfter string `json:"refreshAfter,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination
	Destination Destination `json:"destination"`
}

// HCPVaultSecretsAppStatus defines the observed state of HCPVaultSecretsApp
type HCPVaultSecretsAppStatus struct {
	// SecretMAC used when deciding whether new Vault secret data should be synced.
	//
	// The controller will compare the "new" Vault secret data to this value using HMAC,
	// if they are different, then the data will be synced to the Destination.
	//
	// The SecretMac is also used to detect drift in the Destination Secret's Data.
	// If drift is detected the data will be synced to the Destination.
	SecretMAC string `json:"secretMAC,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// HCPVaultSecretsApp is the Schema for the hcpvaultsecretsapps API
type HCPVaultSecretsApp struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HCPVaultSecretsAppSpec   `json:"spec,omitempty"`
	Status HCPVaultSecretsAppStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// HCPVaultSecretsAppList contains a list of HCPVaultSecretsApp
type HCPVaultSecretsAppList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HCPVaultSecretsApp `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HCPVaultSecretsApp{}, &HCPVaultSecretsAppList{})
}
