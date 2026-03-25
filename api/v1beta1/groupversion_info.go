// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package v1beta1 contains API Schema definitions for the secrets v1beta1 API group
// +kubebuilder:object:generate=true
// +groupName=secrets.hashicorp.com
package v1beta1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "secrets.hashicorp.com", Version: "v1beta1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
