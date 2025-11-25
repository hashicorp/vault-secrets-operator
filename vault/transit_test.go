package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithKeyVersion(t *testing.T) {
	tests := []struct {
		name string
		v    uint
	}{
		{"key version 1", 1},
		{"key version 42", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := WithKeyVersion(tt.v)
			m := make(map[string]any)

			opts(m)

			require.Contains(t, m, "key_version")
			assert.Equal(t, tt.v, m["key_version"])
		})
	}
}
