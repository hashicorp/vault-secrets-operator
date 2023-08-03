// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package errors

import "fmt"

var InvalidCredentialDataError = fmt.Errorf("invalid credential data")

// IncompleteCredentialError occurs whenever the credential data has empty
// values or missing keys.
type IncompleteCredentialError struct {
	keys []string
}

func (i *IncompleteCredentialError) Error() string {
	return fmt.Sprintf("unset or empty required keys %v", i.keys)
}

func NewIncompleteCredentialError(keys ...string) *IncompleteCredentialError {
	return &IncompleteCredentialError{
		keys: keys,
	}
}
