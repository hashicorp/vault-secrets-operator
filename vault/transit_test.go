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
			opts := WithKeyVersion(tt.v)
			m := make(map[string]any)

			opts(m)

			require.Contains(t, m, "key_version")
			assert.Equal(t, tt.v, m["key_version"])
		})
	}
}
