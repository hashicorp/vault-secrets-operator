// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tests to ensure all allowedSpringFuncs are registered in the funcMap
func Test_funcMap(t *testing.T) {
	expected := allowedSpringFuncs
	var actual []string
	for k := range funcMap {
		actual = append(actual, k)
	}

	slices.Sort(actual)
	assert.Equal(t, actual, expected)
}
