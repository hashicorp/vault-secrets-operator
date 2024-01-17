// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecretTransformationStatus defines the observed state of SecretTransformation
type SecretTransformationStatus struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// SecretTransformation is the Schema for the secrettransformations API
type SecretTransformation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretTransformationSpec   `json:"spec,omitempty"`
	Status SecretTransformationStatus `json:"status,omitempty"`
}

// SecretTransformationSpec defines the desired state of SecretTransformation
type SecretTransformationSpec struct {
	// Templates maps a template name to its Template. Templates are always included
	// in the rendered K8s Secret with the specified key.
	Templates map[string]Template `json:"templates,omitempty"`
	// SourceTemplates are never included in the rendered K8s Secret, they can be
	// used to provide common template definitions, etc.
	SourceTemplates []SourceTemplate `json:"sourceTemplates,omitempty"`
	// Includes contains regex patterns of keys that should be included in the K8s
	// Secret Data.
	Includes []string `json:"includes,omitempty"`
	// Excludes contains regex pattern for keys that should be excluded from the K8s
	// Secret Data.
	Excludes []string `json:"excludes,omitempty"`
}

// SourceTemplate provides source templating configuration.
type SourceTemplate struct {
	Name string `json:"name,omitempty"`
	// Text contains the Go text template format. The template
	// references attributes from the data structure of the source secret.
	// Refer to https://pkg.go.dev/text/template for more information.
	Text string `json:"text"`
}

//+kubebuilder:object:root=true

// SecretTransformationList contains a list of SecretTransformation
type SecretTransformationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretTransformation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretTransformation{}, &SecretTransformationList{})
}
