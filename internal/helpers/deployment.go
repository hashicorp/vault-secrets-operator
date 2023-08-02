// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	deploymentShutdown         = "deploymentShutdown"
	inMemoryVaultTokensRevoked = "inMemoryVaultTokensRevoked"
	StringTrue                 = "true"
	managerConfigMapNameEnv    = "MANAGER_CONFIGMAP_NAME"
)

func getManagerConfigMapName() string {
	return os.Getenv(managerConfigMapNameEnv)
}

func WatchManagerConfigMap(ctx context.Context, c client.WithWatch) (watch.Interface, error) {
	name := getManagerConfigMapName()
	if name == "" {
		return nil, fmt.Errorf("failed to parse manager configmap name from %s", managerConfigMapNameEnv)
	}

	var configMap corev1.ConfigMap
	err := c.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace, Name: name}, &configMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get manager configmap")
	}

	list := corev1.ConfigMapList{Items: []corev1.ConfigMap{configMap}}
	watcher, err := c.Watch(ctx, &list)
	if err != nil {
		return nil, fmt.Errorf("failed to watch the manager configmap err=%s", err)
	}
	return watcher, nil
}

type OnConfigMapChange func(context.Context, *corev1.ConfigMap, client.Client) error

func WaitForManagerConfigMapModified(ctx context.Context, logger logr.Logger, watcher watch.Interface, c client.Client, evaluator func(*corev1.ConfigMap) bool, onChanges ...OnConfigMapChange) {
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "Operator manager context canceled")
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if m, ok := event.Object.(*corev1.ConfigMap); ok {
					if evaluator(m) {
						for _, onChange := range onChanges {
							onChange(ctx, m, c)
						}
						return
					}
				}
			}
		}
	}
}

func IsDeploymentShutdown(m *corev1.ConfigMap) bool {
	val, ok := m.Data[deploymentShutdown]
	return ok && val == StringTrue
}

func IsInMemoryVaultTokensRevoked(m *corev1.ConfigMap) bool {
	val, ok := m.Data[inMemoryVaultTokensRevoked]
	return ok && val == StringTrue
}

func SetConfigMapDeploymentShutdown(ctx context.Context, c client.Client) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		deploymentShutdown: StringTrue,
	})
}

func SetConfigMapInMemoryVaultTokensRevoked(ctx context.Context, c client.Client) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		inMemoryVaultTokensRevoked: StringTrue,
	})
}

func updateManagerConfigMap(ctx context.Context, c client.Client, data map[string]string) error {
	name := getManagerConfigMapName()
	if name == "" {
		return fmt.Errorf("failed to parse manager configmap name from %s", managerConfigMapNameEnv)
	}

	var configMap corev1.ConfigMap
	err := c.Get(ctx, client.ObjectKey{Namespace: common.OperatorNamespace, Name: name}, &configMap)
	for k, v := range data {
		configMap.Data[k] = v
	}

	if err = c.Update(ctx, &configMap, &client.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update the manager ConfigMap data=%v", data)
	}
	return nil
}
