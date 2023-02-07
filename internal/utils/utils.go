// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	// used for monkey patching tests
	saRootDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	ErrNoCurrentNamespace = errors.New("could not determine current namespace")
)

// GetCurrentNamespace returns the "current" namespace,
// as it is configured in the default service account's namespace file.
// The namespace file should be accessible when running in a cluster.
func GetCurrentNamespace() (string, error) {
	filename := filepath.Join(saRootDir, "namespace")
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoCurrentNamespace, err)
	}

	return string(bytes.Trim(b, " ")), nil
}
