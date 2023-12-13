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
	// TemplateSpecs maps a template name to its TemplateSpec.
	TemplateSpecs map[string]TemplateSpec `json:"templateSpecs,omitempty"`
	// FieldFilter provides filtering of the source secret data before it is stored.
	// Templated fields are not affected by filtering.
	FieldFilter FieldFilter `json:"fieldFilter,omitempty"`
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
