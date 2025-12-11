package vault

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithKeyVersion(t *testing.T) {
	tests := []struct {
		name string
		v    uint
	}{
		{
			name: "key version 1",
			v:    1,
		},
		{
			name: "key version 42",
			v:    42,
		},
		{
			name: "key version 10000",
			v:    10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithKeyVersion(tt.v)

			req := &TransitRequestOptions{
				Params:  make(map[string]any),
				Headers: make(http.Header),
			}

			opt(req)

			require.Contains(t, req.Params, "key_version")
			assert.Equal(t, tt.v, req.Params["key_version"])
		})
	}
}

func TestWithNamespace(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		wantSet   bool
	}{
		{
			name:      "sets namespace header",
			namespace: "foo/namespace",
			wantSet:   true,
		},
		{
			name:      "empty namespace does nothing",
			namespace: "",
			wantSet:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := WithNamespace(tt.namespace)

			req := &TransitRequestOptions{
				Params:  make(map[string]any),
				Headers: make(http.Header),
			}

			opt(req)

			got := req.Headers.Get("X-Vault-Namespace")
			if tt.wantSet {
				require.Equal(t, tt.namespace, got)
			} else {
				require.Equal(t, "", got)
			}
		})
	}
}
