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
	Create bool `json:"create,omitempty"`
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
	// TemplateSpecs contain the template configuration that is specific to this
	// syncable secret custom resource. Each template spec will be rendered in order
	// of configuration.
	TemplateSpecs []TemplateSpec `json:"templateSpecs,omitempty"`
	// TemplateRefs contain references to template configuration that is provided
	// by another K8s resource (ConfigMap only).
	TemplateRefs []TemplateRef `json:"templateRefs,omitempty"`
	// FieldFilter provides filtering of the source secret data before it is stored.
	// Templated fields are not affected by filtering.
	FieldFilter FieldFilter `json:"fieldFilter,omitempty"`
}

// TemplateSpec provides inline templating configuration.
type TemplateSpec struct {
	// Name of the template. When Source is false, Name will be used as the key to
	// the rendered secret data.
	Name string `json:"name"`
	// Text contains the Go template in text format. The template
	// references attributes from the data structure of the source secret.
	Text string `json:"text"`
	// Source the template, the spec will not be rendered to the K8s Secret data.
	Source bool `json:"source,omitempty"`
}

// TemplateRefSpec points to templating text that is stored in an external K8s
// resource.
type TemplateRefSpec struct {
	// Name of the template. When Source is false, Name will be used as the key to
	// the rendered secret data.
	Name string `json:"name,omitempty"`
	// Key to the template text in the ConfigMap's data.
	Key string `json:"key"`
	// Source the template when true, this spec will not be rendered to the K8s Secret data.
	Source bool `json:"source,omitempty"`
}

// TemplateRef contains the configuration for accessing templates from an
// external Kubernetes resource. TemplateRefs can be shared across all
// syncable secret custom resources. If a template contains confidential
// information a Kubernetes Secret should be used along with a secure RBAC
// config, otherwise a Configmap should suffice.
// Supported resource types are: ConfigMap, Secret
type TemplateRef struct {
	// Namespace of the resource.
	Namespace string `json:"namespace,omitempty"`
	// Name of the resource.
	Name string `json:"name"`
	// Names of the templates found in the referenced resource. The name should be a
	// key in the referenced resource's data. The value should be a valid Go text
	// template. Refer to https://pkg.go.dev/text/template for more information.
	Specs []TemplateRefSpec `json:"specs"`
}

// FieldFilter can be used to filter the secret data that is stored in the K8s
// Secret Destination. Filters will not be applied to templated fields, those
// will always be included in the Destination K8s Secret. Exclusion filters are
// always applied first.
type FieldFilter struct {
	// Includes contains regex patterns of keys that should be included in the K8s
	// Secret Data.
	Includes []string `json:"includes,omitempty"`
	// Excludes contains regex pattern for keys that should be excluded from the K8s
	// Secret Data.
	Excludes []string `json:"excludes,omitempty"`
}
