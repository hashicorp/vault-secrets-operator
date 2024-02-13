// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HCPVaultSecretsAppSpec defines the desired state of HCPVaultSecretsApp
type HCPVaultSecretsAppSpec struct {
	// AppName of the Vault Secrets Application that is to be synced.
	AppName string `json:"appName"`
	// HCPAuthRef to the HCPAuth resource, can be prefixed with a namespace, eg:
	// `namespaceA/vaultAuthRefB`. If no namespace prefix is provided it will default
	// to the namespace of the HCPAuth CR. If no value is specified for HCPAuthRef the
	// Operator will default to the `default` HCPAuth, configured in the operator's
	// namespace.
	HCPAuthRef string `json:"hcpAuthRef,omitempty"`
	// RefreshAfter a period of time, in duration notation e.g. 30s, 1m, 24h
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern="^([0-9]+(\\.[0-9]+)?(s|m|h))$"
	// +kubebuilder:default="600s"
	RefreshAfter string `json:"refreshAfter,omitempty"`
	// RolloutRestartTargets should be configured whenever the application(s)
	// consuming the HCP Vault Secrets App does not support dynamically reloading a
	// rotated secret. In that case one, or more RolloutRestartTarget(s) can be
	// configured here. The Operator will trigger a "rollout-restart" for each target
	// whenever the Vault secret changes between reconciliation events. See
	// RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`
	// Destination provides configuration necessary for syncing the HCP Vault
	// Application secrets to Kubernetes.
	Destination Destination `json:"destination"`
}

// HCPVaultSecretsAppStatus defines the observed state of HCPVaultSecretsApp
type HCPVaultSecretsAppStatus struct {
	// LastGeneration is the Generation of the last reconciled resource.
	LastGeneration int64 `json:"lastGeneration"`
	// SecretMAC used when deciding whether new Vault secret data should be synced.
	//
	// The controller will compare the "new" HCP Vault Secrets App data to this value
	// using HMAC, if they are different, then the data will be synced to the
	// Destination.
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
