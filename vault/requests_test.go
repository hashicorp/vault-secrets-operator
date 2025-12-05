// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_kvReadRequestV2_Path(t *testing.T) {
	tests := []struct {
		name  string
		mount string
		path  string
		want  string
	}{
		{
			name:  "basic",
			mount: "foo",
			path:  "baz",
			want:  "foo/data/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &kvReadRequestV2{
				mount: tt.mount,
				path:  tt.path,
			}
			assert.Equalf(t, tt.want, r.Path(), "Path()")
		})
	}
}

func Test_kvReadRequestV2_Values(t *testing.T) {
	tests := []struct {
		name    string
		version int
		want    url.Values
	}{
		{
			name:    "without-zero-version",
			version: 0,
			want:    nil,
		},
		{
			name:    "with-negative-version",
			version: -1,
			want:    nil,
		},
		{
			name:    "with-version",
			version: 1,
			want: map[string][]string{
				"version": {"1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &kvReadRequestV2{
				version: tt.version,
			}
			assert.Equalf(t, tt.want, r.Values(), "Values()")
		})
	}
}

func Test_kvReadRequestV1_Path(t *testing.T) {
	tests := []struct {
		name  string
		mount string
		path  string
		want  string
	}{
		{
			name:  "basic",
			mount: "foo",
			path:  "baz",
			want:  "foo/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &kvReadRequestV1{
				mount: tt.mount,
				path:  tt.path,
			}
			assert.Equalf(t, tt.want, r.Path(), "Path()")
		})
	}
}

func Test_defaultReadRequest_Path(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "basic",
			path: "foo/baz",
			want: "foo/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &defaultReadRequest{
				path: tt.path,
			}
			assert.Equalf(t, tt.want, r.Path(), "Path()")
		})
	}
}

func Test_defaultReadRequest_Values(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
		want   url.Values
	}{
		{
			name:   "without-values",
			values: nil,
			want:   nil,
		},
		{
			name: "with-values",
			values: map[string][]string{
				"baz": {"buz", "qux"},
			},
			want: map[string][]string{
				"baz": {"buz", "qux"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &defaultReadRequest{
				values: tt.values,
			}
			assert.Equalf(t, tt.want, r.Values(), "Values()")
		})
	}
}

func Test_defaultWriteRequest_Path(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "basic",
			path: "foo/baz",
			want: "foo/baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &defaultWriteRequest{
				path: tt.path,
			}
			assert.Equalf(t, tt.want, r.Path(), "Path()")
		})
	}
}

func Test_defaultWriteRequest_Params(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   map[string]any
	}{
		{
			name:   "without-params",
			params: nil,
			want:   nil,
		},
		{
			name: "with-params",
			params: map[string]any{
				"baz": []string{"buz", "qux"},
			},
			want: map[string]any{
				"baz": []string{"buz", "qux"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &defaultWriteRequest{
				params: tt.params,
			}
			assert.Equalf(t, tt.want, r.Data(), "Data()")
		})
	}
}
