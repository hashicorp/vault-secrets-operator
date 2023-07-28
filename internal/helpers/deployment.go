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
	DeploymentShutdown         = "DeploymentShutdown"
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

type BeforeShutdown func(context.Context, *corev1.ConfigMap, client.Client) error

func WaitForDeploymentShutdown(ctx context.Context, logger logr.Logger, watcher watch.Interface, c client.Client, funcs ...BeforeShutdown) {
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "Operator manager context canceled")
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if m, ok := event.Object.(*corev1.ConfigMap); ok {
					for _, f := range funcs {
						f(ctx, m, c)
					}
				}
			}
		}
	}
}

func WaitForInMemoryVaultTokensRevoked(ctx context.Context, logger logr.Logger, watcher watch.Interface) {
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "Operator manager context canceled")
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if m, ok := event.Object.(*corev1.ConfigMap); ok {
					if val, ok := m.Data[inMemoryVaultTokensRevoked]; ok && val == StringTrue {
						return
					}
				}
			}
		}
	}
}

func SetConfigMapDeploymentShutdown(ctx context.Context, c client.Client) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		DeploymentShutdown: StringTrue,
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
