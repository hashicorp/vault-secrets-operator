// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"reflect"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/hashicorp/vault-secrets-operator/helpers"
)

func syncableSecretPredicate(syncReg *SyncRegistry) predicate.Predicate {
	return predicate.Or(
		predicate.GenerationChangedPredicate{},
		// needed for template rendering
		&annotationChangedPredicate{syncReg: syncReg},
		// needed for template rendering
		&labelChangedPredicate{syncReg: syncReg},
	)
}

type annotationChangedPredicate struct {
	syncReg *SyncRegistry
	predicate.AnnotationChangedPredicate
}

// Update implements default UpdateEvent filter for validating annotation change. On
// change update the SyncRegistry if set.
func (p *annotationChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		return false
	}
	if e.ObjectNew == nil {
		return false
	}

	if !reflect.DeepEqual(e.ObjectNew.GetAnnotations(), e.ObjectOld.GetAnnotations()) {
		if p.syncReg != nil {
			p.syncReg.Add(client.ObjectKeyFromObject(e.ObjectNew))
		}
		return true
	}

	return false
}

type labelChangedPredicate struct {
	syncReg *SyncRegistry
	predicate.LabelChangedPredicate
}

// Update implements default UpdateEvent filter for validating label change. On
// change update the SyncRegistry if set.
func (p *labelChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		return false
	}
	if e.ObjectNew == nil {
		return false
	}

	if !reflect.DeepEqual(e.ObjectNew.GetLabels(), e.ObjectOld.GetLabels()) {
		if p.syncReg != nil {
			p.syncReg.Add(client.ObjectKeyFromObject(e.ObjectNew))
		}
		return true
	}

	return false
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

// secretDataChangedPredicate lets Update events through only when a Secret's
// .Data has actually changed, so that metadata-only updates (labels,
// annotations, status, resourceVersion bumps with unchanged .Data) never
// reach the event handler and trigger an unnecessary reconcile. Create,
// Delete, and Generic events are ignored, since those are already covered by
// the existing deletion/creation watch handling.
type secretDataChangedPredicate struct{}

func (secretDataChangedPredicate) Create(_ event.CreateEvent) bool {
	return false
}

func (secretDataChangedPredicate) Delete(_ event.DeleteEvent) bool {
	return false
}

func (secretDataChangedPredicate) Generic(_ event.GenericEvent) bool {
	return false
}

func (secretDataChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	oldSecret, ok := e.ObjectOld.(*corev1.Secret)
	if !ok {
		return false
	}

	newSecret, ok := e.ObjectNew.(*corev1.Secret)
	if !ok {
		return false
	}

	return !reflect.DeepEqual(oldSecret.Data, newSecret.Data)
}
