// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/vault-secrets-operator/internal/common"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var random = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

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

// RemoveAllFinalizers is responsible for removing all finalizers added by the controller to prevent
// finalizers from going stale when the controller is being deleted. This function should only be called by the
// leader when the deployment has replicas, and only called when the deployment has a deletionTimestamp.
func RemoveAllFinalizers(shutdownCtx context.Context, c client.Client, log logr.Logger, allNamespaces bool) error {
	// opts := client.ListOptions{}
	opts := []client.ListOption{
		client.InNamespace(common.OperatorNamespace),
	}
	// We don't need to be too restrictive for this filter because we own all of these resources anyways.
	// However, we may want to only remove those in the operator's namespace, in which case restrict it.
	// if allNamespaces != true {
	//opts.Namespace = common.OperatorNamespace
	//}
	// Fetch all custom resources via a list and call RemoveFinalizer() on each resource.
	// Do this for each resource type:
	// * VaultAuthMethod
	// * VaultConnection
	// * VaultDynamicSecret
	// * VaultStaticSecret
	// * VaultPKISecret

	vamList := &secretsv1alpha1.VaultAuthList{}
	err := c.List(shutdownCtx, vamList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultAuth resources")
	}
	removeFinalizers(shutdownCtx, c, log, vamList, vaultAuthFinalizer)

	vcList := &secretsv1alpha1.VaultConnectionList{}
	err = c.List(shutdownCtx, vcList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultConnection resources")
	}
	removeFinalizers(shutdownCtx, c, log, vcList, vaultConnectionFinalizer)

	vdsList := &secretsv1alpha1.VaultDynamicSecretList{}
	err = c.List(shutdownCtx, vdsList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultDynamicSecret resources")
	}
	removeFinalizers(shutdownCtx, c, log, vdsList, vaultDynamicSecretFinalizer)

	vssList := &secretsv1alpha1.VaultStaticSecretList{}
	err = c.List(shutdownCtx, vssList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultStaticSecret resources")
	}
	removeFinalizers(shutdownCtx, c, log, vssList, vaultStaticSecretFinalizer)

	vpkiList := &secretsv1alpha1.VaultPKISecretList{}
	err = c.List(shutdownCtx, vpkiList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultPKISecret resources")
	}
	removeFinalizers(shutdownCtx, c, log, vpkiList, vaultPKIFinalizer)
	return nil
}

func removeFinalizers(shutdownCtx context.Context, c client.Client, log logr.Logger, objs interface{}, finalizerStr string) error {
	cnt := 0
	switch finalizerStr {
	case vaultAuthFinalizer:
		vamL := objs.(*secretsv1alpha1.VaultAuthList)
		for _, x := range vamL.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, finalizerStr) {
				log.Info(fmt.Sprintf("updating finalizer for Auth %s", x.Name))
				if err := c.Update(shutdownCtx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("unable to update finalizer for %s: %s", vaultAuthFinalizer, x.Name))
				}
			}
		}
	case vaultPKIFinalizer:
		vamL := objs.(*secretsv1alpha1.VaultPKISecretList)
		for _, x := range vamL.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, finalizerStr) {
				log.Info(fmt.Sprintf("updating finalizer for PKI %s", x.Name))
				if err := c.Update(shutdownCtx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("unable to update finalizer for %s: %s", vaultPKIFinalizer, x.Name))
				}
			}
		}
	case vaultConnectionFinalizer:
		vamL := objs.(*secretsv1alpha1.VaultConnectionList)
		for _, x := range vamL.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, finalizerStr) {
				log.Info(fmt.Sprintf("updating finalizer for Connection %s", x.Name))
				if err := c.Update(shutdownCtx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("unable to update finalizer for %s: %s", vaultConnectionFinalizer, x.Name))
				}
			}
		}
	case vaultStaticSecretFinalizer:
		vamL := objs.(*secretsv1alpha1.VaultStaticSecretList)
		for _, x := range vamL.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, finalizerStr) {
				log.Info(fmt.Sprintf("updating finalizer for StaticSecret %s", x.Name))
				if err := c.Update(shutdownCtx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("unable to update finalizer for %s: %s", vaultStaticSecretFinalizer, x.Name))
				}
			}
		}
	case vaultDynamicSecretFinalizer:
		vamL := objs.(*secretsv1alpha1.VaultDynamicSecretList)
		for _, x := range vamL.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, finalizerStr) {
				log.Info(fmt.Sprintf("updating finalizer for DynamicSecret %s", x.Name))
				if err := c.Update(shutdownCtx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("unable to update finalizer for %s: %s", vaultDynamicSecretFinalizer, x.Name))
				}
			}
		}
	}
	log.Info(fmt.Sprintf("removed %d finalizers of type: %s", cnt, finalizerStr))
	return nil
}
