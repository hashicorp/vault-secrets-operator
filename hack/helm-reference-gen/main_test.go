// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test various smaller cases and special cases.
func Test(t *testing.T) {
	cases := map[string]struct {
		Input string
		Exp   string
	}{
		"string value": {
			Input: `---
# Line 1
# Line 2
key: value`,
			Exp: `- [$key$](#h-key)

## All Values

### key ((#h-key))

- $key$ ((#v-key)) ($string: value$) - Line 1\n  Line 2
`,
		},
		"integer value": {
			Input: `---
# Line 1
# Line 2
replicas: 3`,
			Exp: `- [$replicas$](#h-replicas)

## All Values

### replicas ((#h-replicas))

- $replicas$ ((#v-replicas)) ($integer: 3$) - Line 1\n  Line 2
`,
		},
		"boolean value": {
			Input: `---
# Line 1
# Line 2
enabled: true`,
			Exp: `- [$enabled$](#h-enabled)

## All Values

### enabled ((#h-enabled))

- $enabled$ ((#v-enabled)) ($boolean: true$) - Line 1\n  Line 2
`,
		},
		"map": {
			Input: `---
# Map line 1
# Map line 2
map:
  # Key line 1
  # Key line 2
  key: value`,
			Exp: `- [$map$](#h-map)

## All Values

### map ((#h-map))

- $map$ ((#v-map)) - Map line 1\n  Map line 2

  - $key$ ((#v-map-key)) ($string: value$) - Key line 1\n    Key line 2
`,
		},
		"map with multiple keys": {
			Input: `---
# Map line 1
# Map line 2
map:
  # Key line 1
  # Key line 2
  key: value
  # Int docs
  int: 1
  # Bool docs
  bool: true`,
			Exp: `- [$map$](#h-map)

## All Values

### map ((#h-map))

- $map$ ((#v-map)) - Map line 1\n  Map line 2

  - $key$ ((#v-map-key)) ($string: value$) - Key line 1
    Key line 2

  - $int$ ((#v-map-int)) ($integer: 1$) - Int docs

  - $bool$ ((#v-map-bool)) ($boolean: true$) - Bool docs
`,
		},
		"null value": {
			Input: `---
# key docs
# @type: string
key: null`,
			Exp: `- [$key$](#h-key)

## All Values

### key ((#h-key))

- $key$ ((#v-key)) ($string: null$) - key docs
`,
		},
		"description with empty line": {
			Input: `---
# line 1
#
# line 2
key: value`,
			Exp: `- [$key$](#h-key)

## All Values

### key ((#h-key))

- $key$ ((#v-key)) ($string: value$) - line 1\n\n  line 2
`,
		},
		"array of strings": {
			Input: `---
# line 1
# @type: array<string>
serverAdditionalDNSSANs: []
`,
			Exp: `- [$serverAdditionalDNSSANs$](#h-serveradditionaldnssans)

## All Values

### serverAdditionalDNSSANs ((#h-serveradditionaldnssans))

- $serverAdditionalDNSSANs$ ((#v-serveradditionaldnssans)) ($array<string>: []$) - line 1
`,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// Swap $ for `.
			input := strings.Replace(c.Input, "$", "`", -1)

			out, err := GenerateDocs(input)
			require.NoError(t, err)

			// Swap $ for `.
			exp := strings.Replace(c.Exp, "$", "`", -1)

			// Swap \n for real \n.
			exp = strings.Replace(exp, "\\n", "\n", -1)

			exp = tocPrefix + exp

			require.Equal(t, exp, out)
		})
	}
}

// Test against a full values file and compare against a golden file.
func TestFullValues(t *testing.T) {
	inputBytes, err := os.ReadFile(filepath.Join("fixtures", "full-values.yaml"))
	require.NoError(t, err)
	expBytes, err := os.ReadFile(filepath.Join("fixtures", "full-values.golden"))
	require.NoError(t, err)

	actual, err := GenerateDocs(string(inputBytes))
	require.NoError(t, err)
	if actual != string(expBytes) {
		require.NoError(t, os.WriteFile(filepath.Join("fixtures", "full-values.actual"), []byte(actual), 0o644))
		require.FailNow(t, "output not equal, actual output to full-values.actual")
	}
}
