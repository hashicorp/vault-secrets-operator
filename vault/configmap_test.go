// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
)

func TestOnShutDown(t *testing.T) {
	ctx := context.Background()
	cache, err := NewClientCache(100, nil, nil)
	require.NoError(t, err)

	clientFactory := cachingClientFactory{
		cache:  cache,
		logger: log.FromContext(ctx),
	}

	client := testutils.NewFakeClient()

	tests := []struct {
		cm       *corev1.ConfigMap
		expected bool
	}{
		{
			&corev1.ConfigMap{
				Data: map[string]string{"anotherKey": "anotherValue"},
			},
			false,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{ConfigMapKeyShutDownMode: ""},
			},
			false,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{ConfigMapKeyShutDownMode: "invalidValue"},
			},
			false,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{ConfigMapKeyShutDownMode: ShutDownModeRevoke.String()},
			},
			true,
		},
		{
			&corev1.ConfigMap{
				Data: map[string]string{ConfigMapKeyShutDownMode: ShutDownModeNoRevoke.String()},
			},
			true,
		},
	}

	for _, tt := range tests {
		onConfigMapChange := OnShutDown(&clientFactory)
		actual := onConfigMapChange(ctx, client, tt.cm)
		assert.Equal(t, tt.expected, actual)

		// we test the next calling of onConfigMapChange should return true without checking the configmap, and
		// false when the ConfigMap data don't have any changes that meet the condition
		// We pass in an empty ConfigMap. This checks if shutDown in OnShutDown's scope was cached correctly, and
		// onConfigMapChange only checks shutDown and returns true
		actual = onConfigMapChange(ctx, client, &corev1.ConfigMap{})
		assert.Equal(t, tt.expected, actual)
	}
}
