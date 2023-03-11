// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"math/rand"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var random = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

func ignoreUpdatePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Ignore updates to CR status in which case metadata.Generation does not change
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
	}
}

func filterNamespacePredicate(allowed []string) predicate.Predicate {
	checkNamespace := func(obj client.Object) bool {
		for _, ns := range allowed {
			if obj.GetNamespace() == ns {
				return true
			}
		}
		return false
	}
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return checkNamespace(e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return checkNamespace(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return checkNamespace(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return checkNamespace(e.Object)
		},
	}
}

// computeHorizonWithJitter returns a time.Duration minus a random offset, with an
// additional random jitter added to reduce pressure on the Reconciler.
// based https://github.com/hashicorp/vault/blob/03d2be4cb943115af1bcddacf5b8d79f3ec7c210/api/lifetime_watcher.go#L381
// If max jitter computed is less than or equal 0, the result will be 0,
// that is done to avoid the divide by zero runtime error. The caller should handle that case.
func computeHorizonWithJitter(minDuration time.Duration) time.Duration {
	jitterMax := 0.1 * float64(minDuration.Nanoseconds())

	u := uint64(jitterMax)
	if u <= 0 {
		return 0
	}
	return minDuration - (time.Duration(jitterMax) + time.Duration(uint64(random.Int63())%u))
}
