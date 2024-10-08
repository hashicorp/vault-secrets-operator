// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

var (
	_ error = (*LeaseTruncatedError)(nil)
	// random is not cryptographically secure, should not be used in any crypto
	// type of operations.
	random                 = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	requeueDurationOnError = time.Second * 5
	// used by monkey patching unit tests
	nowFunc = time.Now
)

const renewalPercentCap = 90

type empty struct{}

// LeaseTruncatedError indicates that the requested lease renewal duration is
// less than expected
type LeaseTruncatedError struct {
	Expected int
	Actual   int
}

func (l *LeaseTruncatedError) Error() string {
	return fmt.Sprintf("lease renewal duration was truncated from %ds to %ds",
		l.Expected, l.Actual)
}

// computeMaxJitter with max as 10% of the duration, and jitter a random amount
// between 0-10%
func computeMaxJitter(duration time.Duration) (maxHorizon float64, jitter uint64) {
	return computeMaxJitterWithPercent(duration, 0.10)
}

// computeMaxJitterDuration with max as 10% of the duration, and jitter a random amount
// between 0-10% as time.Duration.
func computeMaxJitterDuration(duration time.Duration) (maxHorizon float64, jitter time.Duration) {
	var j uint64
	maxHorizon, j = computeMaxJitterWithPercent(duration, 0.10)
	jitter = time.Duration(j)

	return
}

// computeMaxJitter with max as a percentage (percent) of the duration, and
// jitter a random amount between 0 up to percent
func computeMaxJitterWithPercent(duration time.Duration, percent float64) (maxHorizon float64, jitter uint64) {
	nanos := duration.Nanoseconds()
	maxHorizon = percent * float64(nanos)
	u := uint64(maxHorizon)
	if u == 0 {
		jitter = 0
	} else {
		jitter = uint64(random.Int63()) % u
	}
	return maxHorizon, jitter
}

// computeMaxJitterDurationWithPercent with max as a percentage (percent) of the duration, and
// jitter a random amount between 0 up to percent
func computeMaxJitterDurationWithPercent(duration time.Duration, percent float64) (float64, time.Duration) {
	maxDuration, jitter := computeMaxJitterWithPercent(duration, percent)
	return maxDuration, time.Duration(jitter)
}

// computeHorizonWithJitter returns a time.Duration minus a random offset, with an
// additional random jitter added to reduce pressure on the Reconciler.
// based https://github.com/hashicorp/vault/blob/03d2be4cb943115af1bcddacf5b8d79f3ec7c210/api/lifetime_watcher.go#L381
func computeHorizonWithJitter(minDuration time.Duration) time.Duration {
	maxHorizon, jitter := computeMaxJitter(minDuration)

	return minDuration - (time.Duration(maxHorizon) + time.Duration(jitter))
}

// capRenewalPercent returns a renewalPercent capped between 0 and 90
// inclusively
func capRenewalPercent(renewalPercent int) (rp int) {
	switch {
	case renewalPercent > renewalPercentCap:
		rp = renewalPercentCap
	case renewalPercent < 0:
		rp = 0
	default:
		rp = renewalPercent
	}
	return rp
}

// computeDynamicHorizonWithJitter returns a time.Duration that is the specified
// percentage of the lease duration, minus some random jitter (up to 10% of
// leaseDuration), to ensure the horizon falls within the specified renewal window
func computeDynamicHorizonWithJitter(leaseDuration time.Duration, renewalPercent int) time.Duration {
	maxHorizon, jitter := computeMaxJitter(leaseDuration)

	return computeStartRenewingAt(leaseDuration, renewalPercent) + time.Duration(maxHorizon) - time.Duration(jitter)
}

// computeStartRenewingAt returns a time.Duration that is the specified
// percentage of the lease duration.
func computeStartRenewingAt(leaseDuration time.Duration, renewalPercent int) time.Duration {
	return time.Duration(float64(leaseDuration.Nanoseconds()) * float64(capRenewalPercent(renewalPercent)) / 100)
}

// RemoveAllFinalizers is responsible for removing all finalizers added by the controller to prevent
// finalizers from going stale when the controller is being deleted.
func RemoveAllFinalizers(ctx context.Context, c client.Client, log logr.Logger) error {
	// To support allNamespaces, do not add the common.OperatorNamespace filter, aka opts := client.ListOptions{}
	opts := []client.ListOption{
		client.InNamespace(common.OperatorNamespace),
	}
	// Fetch all custom resources managed by the controller and remove any finalizers that we control.
	// Do this for each resource type:
	// * VaultAuthMethod
	// * VaultConnection
	// * VaultDynamicSecret
	// * VaultStaticSecret <- not currently implemented
	// * VaultPKISecret

	vamList := &secretsv1beta1.VaultAuthList{}
	err := c.List(ctx, vamList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultAuth resources")
	}
	removeFinalizers(ctx, c, log, vamList)

	vcList := &secretsv1beta1.VaultConnectionList{}
	err = c.List(ctx, vcList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultConnection resources")
	}
	removeFinalizers(ctx, c, log, vcList)

	vdsList := &secretsv1beta1.VaultDynamicSecretList{}
	err = c.List(ctx, vdsList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultDynamicSecret resources")
	}
	removeFinalizers(ctx, c, log, vdsList)

	vpkiList := &secretsv1beta1.VaultPKISecretList{}
	err = c.List(ctx, vpkiList, opts...)
	if err != nil {
		log.Error(err, "Unable to list VaultPKISecret resources")
	}
	removeFinalizers(ctx, c, log, vpkiList)
	return nil
}

// removeFinalizers removes specific finalizers from each CR type and updates the resource if necessary.
// Errors are ignored in this case so that we can do the best effort attempt to remove *all* finalizers, even
// if one or two have problems.
func removeFinalizers(ctx context.Context, c client.Client, log logr.Logger, objs client.ObjectList) {
	cnt := 0
	switch t := objs.(type) {
	case *secretsv1beta1.VaultAuthList:
		for _, x := range t.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, vaultAuthFinalizer) {
				log.Info(fmt.Sprintf("Updating finalizer for Auth %s", x.Name))
				if err := c.Update(ctx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("Unable to update finalizer for %s: %s", vaultAuthFinalizer, x.Name))
				}
			}
		}
	case *secretsv1beta1.VaultPKISecretList:
		for _, x := range t.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, vaultPKIFinalizer) {
				log.Info(fmt.Sprintf("Updating finalizer for PKI %s", x.Name))
				if err := c.Update(ctx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("Unable to update finalizer for %s: %s", vaultPKIFinalizer, x.Name))
				}
			}
		}
	case *secretsv1beta1.VaultConnectionList:
		for _, x := range t.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, vaultConnectionFinalizer) {
				log.Info(fmt.Sprintf("Updating finalizer for Connection %s", x.Name))
				if err := c.Update(ctx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("Unable to update finalizer for %s: %s", vaultConnectionFinalizer, x.Name))
				}
			}
		}
	case *secretsv1beta1.VaultDynamicSecretList:
		for _, x := range t.Items {
			cnt++
			if controllerutil.RemoveFinalizer(&x, vaultDynamicSecretFinalizer) {
				log.Info(fmt.Sprintf("Updating finalizer for DynamicSecret %s", x.Name))
				if err := c.Update(ctx, &x, &client.UpdateOptions{}); err != nil {
					log.Error(err, fmt.Sprintf("Unable to update finalizer for %s: %s", vaultDynamicSecretFinalizer, x.Name))
				}
			}
		}
	}
	log.Info(fmt.Sprintf("Removed %d finalizers", cnt))
}

func parseDurationString(duration, path string, min time.Duration) (time.Duration, error) {
	var err error
	var d time.Duration
	if duration != "" {
		d, err = time.ParseDuration(duration)
		if err != nil {
			return 0, fmt.Errorf(
				"invalid value %q for %s, %w",
				duration, path, err)
		}
		if d < min {
			return 0, fmt.Errorf(
				"invalid value %q for %s, below the minimum allowed value %s",
				duration, path, min)
		}
	}
	return d, nil
}

func isInWindow(t1, t2 time.Time) bool {
	return t1.After(t2) || t1.Equal(t2)
}

// maybeAddFinalizer updates client.Object with finalizer if it is not already
// set. Return true if the object was updated, in which case the object's
// ResourceVersion will have changed. This update should be handled by in the
// caller.
func maybeAddFinalizer(ctx context.Context, c client.Client, o client.Object, finalizer string) (bool, error) {
	if o.GetDeletionTimestamp() == nil && !controllerutil.ContainsFinalizer(o, finalizer) {
		// always call maybeAddFinalizer() after client.Client.Status.Update() to avoid
		// API validation errors due to changes to the status schema.
		logger := log.FromContext(ctx).WithValues("finalizer", finalizer)
		logger.V(consts.LogLevelTrace).Info("Adding finalizer",
			"finalizer", finalizer)
		controllerutil.AddFinalizer(o, finalizer)
		if err := c.Update(ctx, o); err != nil {
			logger.Error(err, "Failed to add finalizer")
			controllerutil.RemoveFinalizer(o, finalizer)
			return false, err
		}

		return true, nil
	}

	return false, nil
}

func waitForStoppedCh(ctx context.Context, stoppedCh chan struct{}) error {
	select {
	case <-stoppedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// updateConditions updates the current conditions with updates, returning a new
// set of metav1.Condition(s). It will update the LastTransitionTime if the condition has
// changed. It will also append new conditions to the existing conditions. All
// updates are deduplicated based on their type and reason.
func updateConditions(current []metav1.Condition, updates ...metav1.Condition) []metav1.Condition {
	seen := make(map[string]bool)
	var ret []metav1.Condition
	for _, newCond := range updates {
		// we key conditions on their type and reason
		// e.g: type=VaultAuthGlobal reason=Available, ...
		key := fmt.Sprintf("%s/%s", newCond.Type, newCond.Reason)
		if seen[key] {
			// drop duplicate conditions
			continue
		}

		seen[key] = true
		var updated bool
		for _, cond := range current {
			if cond.Type == newCond.Type && cond.Reason == newCond.Reason {
				if cond.Status != newCond.Status {
					newCond.LastTransitionTime = metav1.NewTime(nowFunc())
				}
				if newCond.LastTransitionTime.IsZero() {
					if cond.LastTransitionTime.IsZero() {
						newCond.LastTransitionTime = metav1.NewTime(nowFunc())
					} else {
						newCond.LastTransitionTime = cond.LastTransitionTime
					}
				}
				ret = append(ret, newCond)
				updated = true
				break
			}
		}
		if !updated {
			if newCond.LastTransitionTime.IsZero() {
				newCond.LastTransitionTime = metav1.NewTime(nowFunc())
			}
			ret = append(ret, newCond)
		}
	}
	return ret
}
