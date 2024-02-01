// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

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
	// +kubebuilder:default=false
	Create bool `json:"create"`
	// Overwrite the destination Secret if it exists and Create is true. This is
	// useful when migrating to VSO from a previous secret deployment strategy.
	// +kubebuilder:default=false
	Overwrite bool `json:"overwrite"`
	// Labels to apply to the Secret. Requires Create to be set to true.
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations to apply to the Secret. Requires Create to be set to true.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Type of Kubernetes Secret. Requires Create to be set to true.
	// Defaults to Opaque.
	Type v1.SecretType `json:"type,omitempty"`
	// Transformation provides configuration for transforming the secret data before
	// it is stored in the Destination.
	Transformation Transformation `json:"transformation,omitempty"`
}

// RolloutRestartTarget provides the configuration required to perform a
// rollout-restart of the supported resources upon Vault Secret rotation.
// The rollout-restart is triggered by patching the target resource's
// 'spec.template.metadata.annotations' to include 'vso.secrets.hashicorp.com/restartedAt'
// with a timestamp value of when the trigger was executed.
// E.g. vso.secrets.hashicorp.com/restartedAt: "2023-03-23T13:39:31Z"
//
// Supported resources: Deployment, DaemonSet, StatefulSet
type RolloutRestartTarget struct {
	// +kubebuilder:validation:Enum={Deployment,DaemonSet,StatefulSet}
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type Transformation struct {
	// Templates maps a template name to its Template. Templates are always included
	// in the rendered K8s Secret, and take precedence over templates defined in a
	// SecretTransformation.
	Templates map[string]Template `json:"templates,omitempty"`
	// TransformationRefs contain references to template configuration from
	// SecretTransformation
	TransformationRefs []TransformationRef `json:"transformationRefs,omitempty"`
	// Includes contains regex patterns of keys that should be included in the K8s
	// Secret Data.
	// FieldFilter can be used to filter the secret data that is stored in the K8s
	// Secret Destination. Filters will not be applied to templated fields, those
	// will always be included in the Destination K8s Secret. Exclusion filters are
	// always applied first.
	Includes []string `json:"includes,omitempty"`
	// Excludes contains regex pattern for keys that should be excluded from the K8s
	// Secret Data.
	// FieldFilter can be used to filter the secret data that is stored in the K8s
	// Secret Destination. Filters will not be applied to templated fields, those
	// will always be included in the Destination K8s Secret. Exclusion filters are
	// always applied first.
	Excludes []string `json:"excludes,omitempty"`
	// ExcludeRaw data from the destination Secret. Exclusion policy can be set
	// globally by including 'exclude-raw` in the '--global-rendering-options'
	// command line flag. The global policy always takes precedence over this
	// configuration.
	// +kubebuilder:default=false
	ExcludeRaw bool `json:"excludeRaw"`
}

// TransformationRef contains the configuration for accessing templates from an
// SecretTransformation resource. TransformationRefs can be shared across all
// syncable secret custom resources.
type TransformationRef struct {
	// Namespace of the SecretTransformation resource.
	Namespace string `json:"namespace,omitempty"`
	// Name of the SecretTransformation resource.
	Name string `json:"name"`
	// TemplateRefs map to a Template found in this TransformationRef. If empty, then
	// all templates from the SecretTransformation will be rendered to the K8s Secret.
	TemplateRefs []TemplateRef `json:"templateRefs,omitempty"`
	// IgnoreIncludes controls whether to use the SecretTransformation's Includes
	// data key filters.
	IgnoreIncludes bool `json:"ignoreIncludes,omitempty"`
	// IgnoreExcludes controls whether to use the SecretTransformation's Excludes
	// data key filters.
	IgnoreExcludes bool `json:"ignoreExcludes,omitempty"`
}

// TemplateRef points to templating text that is stored in a
// SecretTransformation custom resource.
type TemplateRef struct {
	// Name of the Template in SecretTransformationSpec.Templates.
	// the rendered secret data.
	Name string `json:"name"`
	// KeyOverride to the rendered template in the Destination secret. If Key is
	// empty, then the Key from reference spec will be used. Set this to override the
	// Key set from the reference spec.
	KeyOverride string `json:"keyOverride,omitempty"`
}

// Template provides templating configuration.
type Template struct {
	// Name of the Template
	Name string `json:"name,omitempty"`
	// Text contains the Go text template format. The template
	// references attributes from the data structure of the source secret.
	// Refer to https://pkg.go.dev/text/template for more information.
	Text string `json:"text"`
}
