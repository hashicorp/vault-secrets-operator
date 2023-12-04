// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

var (
	_                      error = (*LeaseTruncatedError)(nil)
	random                       = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
	requeueDurationOnError       = time.Second * 5
	// used by monkey patching unit tests
	nowFunc = time.Now
)

const renewalPercentCap = 90

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
// Errors are ignored in this case so that we can do a best effort attempt to remove *all* finalizers, even
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
