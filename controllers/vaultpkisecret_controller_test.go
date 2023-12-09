// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func Test_computePKIRenewalWindow(t *testing.T) {
	ctx := context.Background()
	// make tests more predictable by using a shared static timestamp and dropping
	// nanoseconds.
	staticNow := time.Unix(time.Now().Unix(), 0)
	defaultNowFunc := func() time.Time { return staticNow }

	type assertFunc func(assert.TestingT, time.Duration, ...interface{}) bool

	newInWindowAssertFunc := func(expected, boundary time.Duration) assertFunc {
		return func(t assert.TestingT, actual time.Duration, msg ...interface{}) bool {
			if assert.LessOrEqual(t, expected, actual, msg...) {
				return assert.LessOrEqual(t, actual, boundary)
			}
			return false
		}
	}
	newNotInWindowAssertFunc := func(expected, boundary time.Duration, withOffset bool) assertFunc {
		return func(t assert.TestingT, actual time.Duration, msg ...interface{}) bool {
			if withOffset {
				// if an offset is specified we expect the horizon+jitter to be between expected
				// and boundary.
				if assert.GreaterOrEqual(t, actual, expected, msg...) {
					return assert.LessOrEqual(t, actual, boundary)
				}
			} else {
				// if an offset is not specified we expect the horizon+jitter to be less than
				// expected and greater than the boundary.
				if assert.LessOrEqual(t, actual, expected, msg...) {
					return assert.GreaterOrEqual(t, actual, boundary)
				}
			}
			return false
		}
	}

	tests := []struct {
		name            string
		o               *secretsv1beta1.VaultPKISecret
		expirationDelta int64
		jitterPercent   float64
		wantInWindow    bool
		assertFunc      assertFunc
		minHorizon      time.Duration
	}{
		{
			name: "in-window-with-offset-overlap",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "30s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 30,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-without-offset-at-expiry",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 0,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-without-offset-beyond-expiry",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: -1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "in-window-with-invalid-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "30 s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: -1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.05*float64(time.Second))),
			wantInWindow:    true,
		},
		{
			name: "not-in-window-computed-horizon-less-than-1s",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 1,
			jitterPercent:   0.05,
			assertFunc:      newInWindowAssertFunc(time.Second*1, time.Duration(1.2*float64(time.Second))),
			wantInWindow:    true,
			minHorizon:      time.Millisecond * 1100,
		},
		{
			name: "not-in-window-with-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "10s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*50, time.Second*60, true),
			wantInWindow:    false,
		},
		{
			name: "not-in-window-without-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec:   secretsv1beta1.VaultPKISecretSpec{},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*60, time.Second*57, false),
			wantInWindow:    false,
		},
		{
			name: "not-in-window-with-invalid-offset",
			o: &secretsv1beta1.VaultPKISecret{
				Spec: secretsv1beta1.VaultPKISecretSpec{
					ExpiryOffset: "10 s",
				},
				Status: secretsv1beta1.VaultPKISecretStatus{},
			},
			expirationDelta: 60,
			jitterPercent:   0.05,
			assertFunc:      newNotInWindowAssertFunc(time.Second*60, time.Second*57, false),
			wantInWindow:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nowFuncOrig := nowFunc
			minHorizonOrig := minHorizon
			if tt.minHorizon > 0 {
				minHorizon = tt.minHorizon
			}
			t.Cleanup(func() {
				nowFunc = nowFuncOrig
				minHorizon = minHorizonOrig
			})

			nowFunc = defaultNowFunc
			now := nowFunc()
			tt.o.Status.Expiration = now.Unix() + tt.expirationDelta
			gotHorizon, gotInWindow := computePKIRenewalWindow(ctx, tt.o, tt.jitterPercent)
			tt.assertFunc(t, gotHorizon, "computePKIRenewalWindow(%v, %v, %v)", ctx, tt.o, tt.jitterPercent)
			assert.Equalf(t, tt.wantInWindow, gotInWindow, "computePKIRenewalWindow(%v, %v, %v)", ctx, tt.o, tt.jitterPercent)
		})
	}
}
