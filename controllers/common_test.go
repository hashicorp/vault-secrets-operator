// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
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

func Test_maybeAddFinalizer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deletionTimestamp := metav1.NewTime(time.Now())

	tests := []struct {
		name           string
		o              client.Object
		create         bool
		finalizer      string
		want           bool
		wantFinalizers []string
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name: "updated",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "updated",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			create:         true,
			finalizer:      vaultAuthFinalizer,
			want:           true,
			wantFinalizers: []string{vaultAuthFinalizer},
			wantErr:        assert.NoError,
		},
		{
			name: "updated-with-multiple",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "updated",
					Finalizers: []string{
						"other",
					},
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			create:         true,
			finalizer:      vaultAuthFinalizer,
			want:           true,
			wantFinalizers: []string{"other", vaultAuthFinalizer},
			wantErr:        assert.NoError,
		},
		{
			name: "not-updated-exists-with-finalizer",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "updated",
					Finalizers: []string{
						vaultAuthFinalizer,
					},
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			create:         true,
			finalizer:      vaultAuthFinalizer,
			want:           false,
			wantFinalizers: []string{vaultAuthFinalizer},
			wantErr:        assert.NoError,
		},
		{
			name: "not-updated-inexistent-with-finalizer",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "updated",
					Finalizers: []string{
						vaultAuthFinalizer,
					},
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			finalizer:      vaultAuthFinalizer,
			want:           false,
			wantFinalizers: []string{vaultAuthFinalizer},
			wantErr:        assert.NoError,
		},
		{
			name: "not-updated-has-deletion-timestamp",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:         "default",
					Name:              "updated",
					DeletionTimestamp: &deletionTimestamp,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			finalizer:      vaultAuthFinalizer,
			want:           false,
			wantFinalizers: []string(nil),
			wantErr:        assert.NoError,
		},
		{
			name: "invalid-not-found",
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "updated",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "kubernetes",
				},
			},
			finalizer:      vaultAuthFinalizer,
			want:           false,
			wantFinalizers: []string{},
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.True(t, apierrors.IsNotFound(err))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testutils.NewFakeClient()
			var origResourceVersion string
			if tt.create {
				require.NoError(t, c.Create(ctx, tt.o))
				origResourceVersion = tt.o.GetResourceVersion()
			}

			got, err := maybeAddFinalizer(ctx, c, tt.o, tt.finalizer)
			if !tt.wantErr(t, err, fmt.Sprintf("maybeAddFinalizer(%v, %v, %v, %v)", ctx, c, tt.o, tt.finalizer)) {
				return
			}

			assert.Equalf(t, tt.want, got, "maybeAddFinalizer(%v, %v, %v, %v)", ctx, c, tt.o, tt.finalizer)
			assert.Equalf(t, tt.wantFinalizers, tt.o.GetFinalizers(), "maybeAddFinalizer(%v, %v, %v, %v)", ctx, c, tt.o, tt.finalizer)

			if tt.create {
				var updated secretsv1beta1.VaultAuth
				if assert.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(tt.o), &updated)) {
					if tt.want {
						assert.NotEqual(t, origResourceVersion, tt.o.GetResourceVersion())
					} else {
						// ensure that the object was not updated.
						assert.Equal(t, origResourceVersion, tt.o.GetResourceVersion())
					}
				}
			}
		})
	}
}

func Test_waitForStoppedCh(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	t.Cleanup(cancel)
	stoppedCh := make(chan struct{}, 1)

	err := waitForStoppedCh(ctx, stoppedCh)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)

	stoppedCh <- struct{}{}
	err = waitForStoppedCh(ctx2, stoppedCh)
	assert.NoError(t, err)
}

func TestVaultAuthReconciler_updateConditions(t *testing.T) {
	t0 := nowFunc().Truncate(time.Second)
	tests := []struct {
		name      string
		current   []metav1.Condition
		updates   []metav1.Condition
		expectLen int
	}{
		{
			name: "no-conditions",
		},
		{
			name: "initial-conditions",
			updates: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
			},
			expectLen: 1,
		},
		{
			name: "unchanged-conditions",
			current: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(t0),
				},
			},
			updates: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
			},
			expectLen: 1,
		},
		{
			name: "unchanged-conditions-no-last-transition-time",
			current: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
			},
			updates: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
			},
			expectLen: 1,
		},
		{
			name: "unchanged-conditions-with-duplicate-updates",
			current: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(t0),
				},
			},
			updates: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(t0),
				},
				{
					Type:               "Available",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(t0),
				},
			},
			expectLen: 1,
		},
		{
			name: "condition-status-transition",
			current: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionFalse,
					LastTransitionTime: metav1.NewTime(nowFunc().Add(-time.Minute)),
				},
				{
					Type:               "Progressing",
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.NewTime(nowFunc().Add(-time.Minute)),
				},
			},
			updates: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
				{
					Type:   "Progressing",
					Status: metav1.ConditionFalse,
				},
			},
			expectLen: 2,
		},
		{
			name: "condition-status-transition-appending-new-condition",
			current: []metav1.Condition{
				{
					Type:               "Available",
					Status:             metav1.ConditionFalse,
					LastTransitionTime: metav1.NewTime(nowFunc().Add(-time.Minute)),
				},
			},
			updates: []metav1.Condition{
				{
					Type:   "Available",
					Status: metav1.ConditionTrue,
				},
				{
					Type:   "Progressing",
					Status: metav1.ConditionFalse,
				},
			},
			expectLen: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origUpdates := make([]metav1.Condition, len(tt.updates))
			seen := make(map[string]bool)
			for idx, cond := range tt.updates {
				key := fmt.Sprintf("%s/%s", cond.Type, cond.Reason)
				if seen[key] {
					continue
				}
				seen[key] = true
				origUpdates[idx] = cond
			}

			got := updateConditions(tt.current, tt.updates...)
			assert.Equalf(t, tt.expectLen, len(got),
				"expected %d conditions, got %d", tt.expectLen, len(got))
			for _, orig := range origUpdates {
				for _, cond := range got {
					if cond.Reason == orig.Reason && orig.Status == cond.Status {
						if orig.LastTransitionTime.IsZero() {
							assert.False(t, cond.LastTransitionTime.IsZero())
						} else {
							assert.Equal(t, orig, cond)
						}
					} else if cond.Reason == orig.Reason && orig.Status != cond.Status {
						assert.Greater(t, cond.LastTransitionTime.Time.Unix(), orig.LastTransitionTime.Time.Unix())
					} else {
						// not updated
						assert.False(t, orig.LastTransitionTime.IsZero())
					}
				}
			}
		})
	}
}
