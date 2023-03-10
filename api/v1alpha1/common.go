// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
)

// Destination provides the configuration that will be applied to the
// destination Kubernetes Secret during a Vault Secret -> K8s Secret sync.
type Destination struct {
	// Name of the Secret
	Name string `json:"name"`
	// Create the destination Secret.
	// If the Secret already exists this should be set to false.
	Create bool `json:"create,omitempty"`
	// Labels to apply to the Secret. Requires Create to be set to true.
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations to apply to the Secret. Requires Create to be set to true.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Type of Kubernetes Secret. Requires Create to be set to true.
	// Defaults to Opaque.
	Type v1.SecretType `json:"type,omitempty"`
}
