// Copyright (c) 2022 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetCurrentNamespace(t *testing.T) {
	tests := []struct {
		name      string
		want      string
		contents  string
		writeFile bool
		fileMode  os.FileMode
		wantErr   bool
	}{
		{
			name:      "basic",
			want:      "baz",
			contents:  "baz",
			writeFile: true,
			fileMode:  0o600,
			wantErr:   false,
		},
		{
			name:      "basic-with-spaces",
			want:      "qux",
			contents:  "  qux ",
			writeFile: true,
			fileMode:  0o600,
			wantErr:   false,
		},
		{
			name:      "error-no-exist",
			writeFile: false,
			wantErr:   true,
		},
		{
			name:      "error-permission-denied",
			writeFile: true,
			fileMode:  0o000,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.writeFile {
				dir := t.TempDir()
				origSARootDir := saRootDir
				t.Cleanup(func() {
					saRootDir = origSARootDir
				})
				saRootDir = dir
				filename := filepath.Join(dir, "namespace")
				if err := os.WriteFile(filename, []byte(tt.contents), tt.fileMode); err != nil {
					t.Fatalf("failed to write namespace file %s, err=%s", filename, err)
				}
			}

			got, err := GetCurrentNamespace()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCurrentNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetCurrentNamespace() got = %v, want %v", got, tt.want)
			}
		})
	}
}
