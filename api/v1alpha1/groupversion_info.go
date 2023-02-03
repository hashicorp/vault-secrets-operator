// Copyright (c) 2022 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package v1alpha1 contains API Schema definitions for the secrets v1alpha1 API group
// +kubebuilder:object:generate=true
// +groupName=secrets.hashicorp.com
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "secrets.hashicorp.com", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
