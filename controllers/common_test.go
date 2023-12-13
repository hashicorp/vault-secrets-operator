// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_parseDurationString(t *testing.T) {
	tests := []struct {
		name    string
		ds      string
		path    string
		min     time.Duration
		want    time.Duration
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "basic",
			ds:      "37s",
			path:    ".spec.foo",
			min:     time.Second * 30,
			want:    time.Second * 37,
			wantErr: assert.NoError,
		},
		{
			name: "below-minimum",
			ds:   "29s",
			path: ".spec.foo",
			min:  time.Second * 30,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("invalid value %q for %s, below the minimum allowed value %s",
						"29s", ".spec.foo", "30s"), i...)
			},
		},
		{
			name: "invalid-duration-string",
			ds:   "10y",
			path: ".spec.foo",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("invalid value %q for %s", "10y", ".spec.foo"), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDurationString(tt.ds, tt.path, tt.min)
			if !tt.wantErr(t, err, fmt.Sprintf("parseDurationString(%v, %v, %v)", tt.ds, tt.path, tt.min)) {
				return
			}
			assert.Equalf(t, tt.want, got, "parseDurationString(%v, %v, %v)", tt.ds, tt.path, tt.min)
		})
	}
}

func Test_computeStartRenewingAt(t *testing.T) {
	type args struct{}
	tests := []struct {
		name           string
		leaseDuration  time.Duration
		renewalPercent int
		want           time.Duration
		wantFunc       func() time.Duration
	}{
		{
			name:           "zero percent",
			leaseDuration:  time.Second * 100,
			renewalPercent: 0,
			want:           0,
		},
		{
			name:           "fifty percent",
			leaseDuration:  time.Second * 100,
			renewalPercent: 50,
			want:           time.Second * 50,
		},
		{
			name:           "ninety percent",
			leaseDuration:  time.Second * 100,
			renewalPercent: 90,
			want:           time.Second * 90,
		},
		{
			name:           "exceed renewalPercentCap",
			leaseDuration:  time.Second * 50,
			renewalPercent: renewalPercentCap + 1,
			want: time.Duration(
				float64((50 * time.Second).Nanoseconds()) * float64(renewalPercentCap) / 100),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want,
				computeStartRenewingAt(tt.leaseDuration, tt.renewalPercent), "computeStartRenewingAt(%v, %v)",
				tt.leaseDuration, tt.renewalPercent,
			)
		})
	}
}

func Test_isInWindow(t *testing.T) {
	epoch := time.Now().Unix()
	tests := []struct {
		name  string
		t1    time.Time
		t2    time.Time
		want  bool
		equal bool
		after bool
	}{
		{
			name:  "in-window-equal",
			t1:    time.Unix(epoch, 0),
			t2:    time.Unix(epoch, 0),
			equal: true,
			want:  true,
		},
		{
			name:  "in-window-after",
			t1:    time.Unix(epoch+1, 0),
			t2:    time.Unix(epoch, 0),
			after: true,
			want:  true,
		},
		{
			name: "not-in-window",
			t1:   time.Unix(epoch, 0),
			t2:   time.Unix(epoch+1, 0),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, isInWindow(tt.t1, tt.t2), "isInWindow(%v, %v)", tt.t1, tt.t2)
			if tt.equal && tt.after {
				require.FailNow(t, "tt.equal and tt.after are mutually exclusive")
			}

			if tt.equal {
				assert.Equal(t, tt.t1, tt.t2)
			}

			if tt.after {
				assert.True(t, tt.t1.After(tt.t2))
			}
		})
	}
}
