// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_dynamicHorizon(t *testing.T) {
	tests := map[string]struct {
		leaseDuration  time.Duration
		renewalPercent int
		expectedMin    time.Duration
		expectedMax    time.Duration
	}{
		"renewalPercent 50": {
			leaseDuration:  time.Duration(15 * time.Second),
			renewalPercent: 50,
			expectedMin:    time.Duration(7.5 * float64(time.Second)),
			expectedMax:    time.Duration(9 * time.Second),
		},
		"renewalPercent 0": {
			leaseDuration:  time.Duration(15 * time.Second),
			renewalPercent: 0,
			expectedMin:    time.Duration(0),
			expectedMax:    time.Duration(1.5 * float64(time.Second)),
		},
		"renewalPercent 90": {
			leaseDuration:  time.Duration(15 * time.Second),
			renewalPercent: 90,
			expectedMin:    time.Duration(13.5 * float64(time.Second)),
			expectedMax:    time.Duration(15 * time.Second),
		},
		"renewalPercent negative": {
			leaseDuration:  time.Duration(15 * time.Second),
			renewalPercent: -60,
			expectedMin:    time.Duration(0),
			expectedMax:    time.Duration(1.5 * float64(time.Second)),
		},
		"renewalPercent over 90": {
			leaseDuration:  time.Duration(15 * time.Second),
			renewalPercent: 1000,
			expectedMin:    time.Duration(13.5 * float64(time.Second)),
			expectedMax:    time.Duration(15 * time.Second),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			horizon := computeDynamicHorizonWithJitter(tc.leaseDuration, tc.renewalPercent)
			assert.GreaterOrEqual(t, horizon, tc.expectedMin)
			assert.LessOrEqual(t, horizon, tc.expectedMax)
		})
	}
}
