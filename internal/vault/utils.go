// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import "strings"

// JoinPath for Vault requests.
func JoinPath(parts ...string) string {
	return strings.Join(parts, "/")
}
