// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import "strings"

// JoinPath for Vault requests.
func JoinPath(parts ...string) string {
	return strings.Join(parts, "/")
}
