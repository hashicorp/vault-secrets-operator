// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package helpers

// MatchingLabels returns true if the `labels` map contains all the required
// labels
func MatchingLabels(requiredLabels, labels map[string]string) bool {
	if len(requiredLabels) == 0 {
		return true
	}

	for k, v := range requiredLabels {
		if labels[k] != v {
			return false
		}
	}

	return true
}
