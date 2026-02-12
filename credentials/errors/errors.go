// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

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
