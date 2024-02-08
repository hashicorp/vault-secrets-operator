// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import "sigs.k8s.io/controller-runtime/pkg/predicate"

func syncableSecretPredicate() predicate.Predicate {
	return predicate.Or(
		predicate.GenerationChangedPredicate{},
		// needed for template rendering
		predicate.AnnotationChangedPredicate{},
		// needed for template rendering
		predicate.LabelChangedPredicate{})
}
