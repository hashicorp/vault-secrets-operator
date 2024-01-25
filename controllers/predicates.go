// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

func syncableSecretPredicate() predicate.Predicate {
	return predicate.Or(
		predicate.GenerationChangedPredicate{},
		// needed for template rendering
		predicate.AnnotationChangedPredicate{},
		// needed for template rendering
		predicate.LabelChangedPredicate{})
}

type secretsPredicate struct{}

func (s *secretsPredicate) Create(_ event.CreateEvent) bool {
	return false
}

func (s *secretsPredicate) Delete(evt event.DeleteEvent) bool {
	return helpers.HasOwnerLabels(evt.Object)
}

func (s *secretsPredicate) Update(_ event.UpdateEvent) bool {
	return false
}

func (s *secretsPredicate) Generic(_ event.GenericEvent) bool {
	return false
}
