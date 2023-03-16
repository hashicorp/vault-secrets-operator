// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateHKDFKey(t *testing.T) {
	tests := []struct {
		name           string
		count          int
		wantErr        assert.ErrorAssertionFunc
		ioReadFullFunc func(io.Reader, []byte) (n int, err error)
		expectedLength int
	}{
		{
			name:           "basic",
			count:          100,
			wantErr:        assert.NoError,
			expectedLength: hkdfKeyLength,
		},
		{
			name:           "error-permission-denied",
			count:          1,
			expectedLength: 0,
			ioReadFullFunc: func(reader io.Reader, bytes []byte) (n int, err error) {
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
			expectedLength: hkdfKeyLength,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ioReadFullFunc != nil {
				t.Cleanup(func() {
					ioReadFull = io.ReadFull
				})
				ioReadFull = tt.ioReadFullFunc
			}

			var last []byte
			for i := 0; i < tt.count; i++ {
				got, err := generateHKDFKey()
				if !tt.wantErr(t, err, fmt.Sprintf("generateHKDFKey()")) {
					return
				}

				assert.Len(t, got, tt.expectedLength, "generateHKDFKey()")
				if last != nil {
					assert.NotEqual(t, got, last, "generateHKDFKey() generated a duplicate key")
				}
				last = got
			}
		})
	}
}
