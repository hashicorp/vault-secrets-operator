// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchingLabels(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		requiredLabels map[string]string
		labels         map[string]string
		want           bool
	}{
		"empty": {
			requiredLabels: map[string]string{},
			labels:         map[string]string{"a": "b"},
			want:           true,
		},
		"empty labels": {
			requiredLabels: map[string]string{"a": "b"},
			labels:         map[string]string{},
			want:           false,
		},
		"match": {
			requiredLabels: map[string]string{
				"a": "b",
				"c": "d",
			},
			labels: map[string]string{
				"c": "d",
				"a": "b",
			},
			want: true,
		},
		"subset": {
			requiredLabels: map[string]string{
				"a": "b",
				"c": "d",
			},
			labels: map[string]string{
				"c": "d",
			},
			want: false,
		},
		"superset match": {
			requiredLabels: map[string]string{
				"a": "b",
				"c": "d",
			},
			labels: map[string]string{
				"a": "b",
				"c": "d",
				"e": "f",
			},
			want: true,
		},
		"mismatch": {
			requiredLabels: map[string]string{
				"a": "b",
				"c": "d",
			},
			labels: map[string]string{
				"a": "b",
				"c": "e",
			},
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := MatchingLabels(tt.requiredLabels, tt.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}
