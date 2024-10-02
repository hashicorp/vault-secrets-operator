// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultPKISecretSpec defines the desired state of VaultPKISecret
type VaultPKISecretSpec struct {
	// VaultAuthRef to the VaultAuth resource, can be prefixed with a namespace,
	// eg: `namespaceA/vaultAuthRefB`. If no namespace prefix is provided it will default to
	// the namespace of the VaultAuth CR. If no value is specified for VaultAuthRef the Operator
	// will default to the `default` VaultAuth, configured in the operator's namespace.
	VaultAuthRef string `json:"vaultAuthRef,omitempty"`

	// Namespace of the secrets engine mount in Vault. If not set, the namespace that's
	// part of VaultAuth resource will be inferred.
	Namespace string `json:"namespace,omitempty"`

	// Mount for the secret in Vault
	Mount string `json:"mount"`

	// Role in Vault to use when issuing TLS certificates.
	Role string `json:"role"`

	// Revoke the certificate when the resource is deleted.
	Revoke bool `json:"revoke,omitempty"`

	// Clear the Kubernetes secret when the resource is deleted.
	Clear bool `json:"clear,omitempty"`

	// ExpiryOffset to use for computing when the certificate should be renewed.
	// The rotation time will be difference between the expiration and the offset.
	// Should be in duration notation e.g. 30s, 120s, etc.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(\\.[0-9]+)?(s|m|h))$`
	ExpiryOffset string `json:"expiryOffset,omitempty"`

	// IssuerRef reference to an existing PKI issuer, either by Vault-generated
	// identifier, the literal string default to refer to the currently
	// configured default issuer, or the name assigned to an issuer.
	// This parameter is part of the request URL.
	IssuerRef string `json:"issuerRef,omitempty"`

	// RolloutRestartTargets should be configured whenever the application(s) consuming the Vault secret does
	// not support dynamically reloading a rotated secret.
	// In that case one, or more RolloutRestartTarget(s) can be configured here. The Operator will
	// trigger a "rollout-restart" for each target whenever the Vault secret changes between reconciliation events.
	// See RolloutRestartTarget for more details.
	RolloutRestartTargets []RolloutRestartTarget `json:"rolloutRestartTargets,omitempty"`

	// Destination provides configuration necessary for syncing the Vault secret
	// to Kubernetes. If the type is set to "kubernetes.io/tls", "tls.key" will
	// be set to the "private_key" response from Vault, and "tls.crt" will be
	// set to "certificate" + "ca_chain" from the Vault response ("issuing_ca"
	// is used when "ca_chain" is empty). The "remove_roots_from_chain=true"
	// option is used with Vault to exclude the root CA from the Vault response.
	Destination Destination `json:"destination"`

	// CommonName to include in the request.
	CommonName string `json:"commonName,omitempty"`

	// AltNames to include in the request
	// May contain both DNS names and email addresses.
	AltNames []string `json:"altNames,omitempty"`

	// IPSans to include in the request.
	IPSans []string `json:"ipSans,omitempty"`

	// The requested URI SANs.
	URISans []string `json:"uriSans,omitempty"`

	// Requested other SANs, in an array with the format
	// oid;type:value for each entry.
	OtherSans []string `json:"otherSans,omitempty"`

	// User ID (OID 0.9.2342.19200300.100.1.1) Subject values to be placed on the
	// signed certificate.
	UserIDs []string `json:"userIDs,omitempty"`

	// TTL for the certificate; sets the expiration date.
	// If not specified the Vault role's default,
	// backend default, or system default TTL is used, in that order.
	// Cannot be larger than the mount's max TTL.
	// Note: this only has an effect when generating a CA cert or signing a CA cert,
	// not when generating a CSR for an intermediate CA.
	// Should be in duration notation e.g. 120s, 2h, etc.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(\\.[0-9]+)?(s|m|h))$`
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
	// LastGeneration is the Generation of the last reconciled resource.
	LastGeneration int64 `json:"lastGeneration"`
	// LastLastRotation of the certificate.
	LastRotation int64 `json:"lastRotation"`
	// SecretMAC used when deciding whether new Vault secret data should be synced.
	//
	// The controller will compare the "new" Vault secret data to this value using HMAC,
	// if they are different, then the data will be synced to the Destination.
	//
	// The SecretMac is also used to detect drift in the Destination Secret's Data.
	// If drift is detected the data will be synced to the Destination.
	SecretMAC string `json:"secretMAC,omitempty"`
	Valid     *bool  `json:"valid"`
	Error     string `json:"error"`
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
		"common_name":             v.Spec.CommonName,
		"alt_names":               strings.Join(v.Spec.AltNames, ","),
		"ip_sans":                 strings.Join(v.Spec.IPSans, ","),
		"uri_sans":                strings.Join(v.Spec.URISans, ","),
		"other_sans":              strings.Join(v.Spec.OtherSans, ","),
		"user_ids":                strings.Join(v.Spec.UserIDs, ","),
		"ttl":                     v.Spec.TTL,
		"not_after":               v.Spec.NotAfter,
		"exclude_cn_from_sans":    v.Spec.ExcludeCNFromSans,
		"remove_roots_from_chain": true,
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
