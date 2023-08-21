// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestOnShutDown(t *testing.T) {
	ctx := context.Background()
	cache, err := NewClientCache(100, nil, nil)
	require.NoError(t, err)

	clientFactory := cachingClientFactory{
		cache:  cache,
		logger: log.FromContext(ctx),
	}

	builder := fake.NewClientBuilder()
	client := builder.Build()

	tests := []struct {
		cm       *corev1.ConfigMap
		expected bool
	}{
		{
			&corev1.ConfigMap{
				Data: map[string]string{"shutDownMode": ""},
			},
			false,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{"anotherKey": "anotherValue"},
			},
			false,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{"shutDownMode": "revoke"},
			},
			true,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{"shutDownMode": "no-revoke"},
			},
			true,
		},
	}

	for _, tt := range tests {
		onConfigMapChange := OnShutDown(&clientFactory)
		actual := onConfigMapChange(ctx, client, tt.cm)
		assert.Equal(t, tt.expected, actual)

		if tt.expected {
			// we test the next calling of onConfigMapChange should return true without checking the configmap
			// we pass in an empty ConfigMap. This will ensure shutDown in OnShutDown's scope was cached correctly, and
			// onConfigMapChange should check shutDown and returns true
			actual = onConfigMapChange(ctx, client, &corev1.ConfigMap{})
			assert.Equal(t, tt.expected, actual)
		}
	}
}
