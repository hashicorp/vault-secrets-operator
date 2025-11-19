// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_validatePath(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "valid-file")
	require.NoError(t, os.WriteFile(validFile, []byte("content"), 0o600))

	// Create a file that's too large (> 1MB)
	largeFile := filepath.Join(tmpDir, "large-file")
	largeContent := make([]byte, 1024*1024+1) // 1MB + 1 byte
	require.NoError(t, os.WriteFile(largeFile, largeContent, 0o600))

	tests := []struct {
		name      string
		path      string
		want      string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid-absolute-path",
			path:      validFile,
			want:      validFile,
			wantError: false,
		},
		{
			name:      "valid-path-with-redundant-separators",
			path:      validFile + "//",
			want:      validFile,
			wantError: false,
		},
		{
			name:      "invalid-relative-path",
			path:      "relative/path",
			wantError: true,
			errorMsg:  "must be an absolute path",
		},
		{
			name:      "invalid-path-with-dotdot-in-middle",
			path:      tmpDir + "/subdir/../../etc/passwd",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "invalid-literal-dotdot-in-path",
			path:      "/tmp/test/../sensitive",
			wantError: true,
			errorMsg:  "path traversal detected",
		},
		{
			name:      "invalid-file-does-not-exist",
			path:      "/nonexistent/file",
			wantError: true,
			errorMsg:  "failed to access file",
		},
		{
			name:      "invalid-file-too-large",
			path:      largeFile,
			wantError: true,
			errorMsg:  "file too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePath(tt.path)
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
