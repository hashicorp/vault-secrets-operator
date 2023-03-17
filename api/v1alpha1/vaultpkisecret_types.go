// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultPKISecretSpec defines the desired state of VaultPKISecret
type VaultPKISecretSpec struct {
	// VaultAuthRef of the VaultAuth resource
	// If no value is specified the Operator will default to the `default` VaultAuth,
	// configured in its own Kubernetes namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`

	// Namespace to get the secret from in Vault
	Namespace string `json:"namespace,omitempty"`

	// Mount for the secret in Vault
	Mount string `json:"mount"`

	// Name of the secret in Vault
	Name string `json:"name"`

	// Revoke the certificate when the resource is deleted.
	Revoke bool `json:"revoke,omitempty"`

	// Clear the Kubernetes secret when the resource is deleted.
	Clear bool `json:"clear,omitempty"`

	// ExpiryOffset to use for computing when the certificate should be renewed.
	// The rotation time will be difference between the expiration and the offset.
	// Should be in duration notation e.g. 30s, 120s, etc.
	// Set to empty string "" to prevent certificate rotation.
	ExpiryOffset string `json:"expiryOffset,omitempty"`

	// IssuerRef reference to an existing PKI issuer, either by Vault-generated
	// identifier, the literal string default to refer to the currently
	// configured default issuer, or the name assigned to an issuer.
	// This parameter is part of the request URL.
	IssuerRef string `json:"issuerRef,omitempty"`

	// Destination provides configuration necessary for syncing the Vault secret to Kubernetes.
	Destination Destination `json:"destination"`

	// CommonName to include in the request.
	CommonName string `json:"commonName"`

	// AltNames to include in the request
	// May contain both DNS names and email addresses.
	AltNames []string `json:"altNames,omitempty"`

	// IPSans to include in the request.
	IPSans []string `json:"ipSans,omitempty"`

	// The requested URI SANs.
	URISans []string `json:"uriSans,omitempty"`

	//Requested other SANs, in an array with the format
	//<oid>;UTF8:<utf8 string value> for each entry.
	OtherSans string `json:"otherSans,omitempty"`

	// TTL for the certificate; sets the expiration date.
	// If not specified the Vault role's default,
	// backend default, or system default TTL is used, in that order.
	// Cannot be larger than the mount's max TTL.
	// Note: this only has an effect when generating a CA cert or signing a CA cert,
	// not when generating a CSR for an intermediate CA.
	// Should be in duration notation e.g. 120s, 2h, etc.
	TTL string `json:"ttl,omitempty"`

	// Format for the certificate. Choices: "pem", "der", "pem_bundle".
	// If "pem_bundle",
	// any private key and issuing cert will be appended to the certificate pem.
	// If "der", the value will be base64 encoded.
	// Default: pem
	Format string `json:"format,omitempty"`

	// PrivateKeyFormat, generally the default will be controlled by the Format
	// parameter as either base64-encoded DER or PEM-encoded DER.
	// However, this can be set to "pkcs8" to have the returned
	// private key contain base64-encoded pkcs8 or PEM-encoded
	// pkcs8 instead.
	// Default: der
	PrivateKeyFormat string `json:"privateKeyFormat,omitempty"`

	// NotAfter field of the certificate with specified date value.
	// The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ
	NotAfter string `json:"notAfter,omitempty"`

	// ExcludeCNFromSans from DNS or Email Subject Alternate Names.
	// Default: false
	ExcludeCNFromSans bool `json:"excludeCNFromSans,omitempty"`
}

// VaultPKISecretStatus defines the observed state of VaultPKISecret
type VaultPKISecretStatus struct {
	SerialNumber string `json:"serialNumber,omitempty"`
	Expiration   int64  `json:"expiration,omitempty"`
	Valid        bool   `json:"valid"`
	Error        string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultPKISecret is the Schema for the vaultpkisecrets API
type VaultPKISecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultPKISecretSpec   `json:"spec,omitempty"`
	Status VaultPKISecretStatus `json:"status,omitempty"`
}

func (v *VaultPKISecret) GetIssuerAPIData() map[string]interface{} {
	m := map[string]interface{}{
		"common_name":          v.Spec.CommonName,
		"alt_names":            v.Spec.AltNames,
		"ip_sans":              v.Spec.IPSans,
		"uri_sans":             v.Spec.URISans,
		"other_sans":           v.Spec.OtherSans,
		"ttl":                  v.Spec.TTL,
		"not_after":            v.Spec.NotAfter,
		"exclude_cn_from_sans": v.Spec.ExcludeCNFromSans,
	}

	if v.Spec.Format != "" {
		m["format"] = v.Spec.Format
	}

	if v.Spec.PrivateKeyFormat != "" {
		m["private_key_format"] = v.Spec.PrivateKeyFormat
	}

	return m
}

//+kubebuilder:object:root=true

// VaultPKISecretList contains a list of VaultPKISecret
type VaultPKISecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultPKISecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultPKISecret{}, &VaultPKISecretList{})
}
