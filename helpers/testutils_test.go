// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func marshalRaw(t *testing.T, d any) []byte {
	t.Helper()

	b, err := json.Marshal(d)
	require.NoError(t, err)
	return b
}
