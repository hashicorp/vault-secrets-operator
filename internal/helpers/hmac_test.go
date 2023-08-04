// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateHMACKey(t *testing.T) {
	tests := []struct {
		name           string
		count          int
		wantErr        assert.ErrorAssertionFunc
		randReadFunc   func([]byte) (n int, err error)
		expectedLength int
	}{
		{
			name:           "basic",
			count:          100,
			wantErr:        assert.NoError,
			expectedLength: hmacKeyLength,
		},
		{
			name:           "error-permission-denied",
			count:          1,
			expectedLength: 0,
			randReadFunc: func(bytes []byte) (n int, err error) {
				return 0, os.ErrPermission
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, os.ErrPermission)
			},
		},
		{
			// verifies that the previous error test put things back in order
			name:           "another",
			count:          100,
			wantErr:        assert.NoError,
			expectedLength: hmacKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.randReadFunc != nil {
				t.Cleanup(func() {
					randRead = rand.Read
				})
				randRead = tt.randReadFunc
			}

			var last []byte
			for i := 0; i < tt.count; i++ {
				got, err := generateHMACKey()
				if !tt.wantErr(t, err, fmt.Sprintf("generateHMACKey()")) {
					return
				}

				assert.Len(t, got, tt.expectedLength, "generateHMACKey()")
				if last != nil {
					assert.NotEqual(t, got, last, "generateHMACKey() generated a duplicate key")
				}
				last = got
			}
		})
	}
}
