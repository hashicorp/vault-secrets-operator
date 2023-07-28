// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func WatchManagerConfigMap(ctx context.Context) (watch.Interface, error) {
	name := getManagerConfigMapName()
	if name == "" {
		return nil, fmt.Errorf("failed to parse manager configmap name from %s", managerConfigMapNameEnv)
	}

	clientCfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get the in-cluster client config err=%s", err)
	}

	clientset, err := kubernetes.NewForConfig(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get a clietset err=%s", err)
	}

	watcher, err := clientset.CoreV1().ConfigMaps(common.OperatorNamespace).Watch(ctx,
		metav1.SingleObject(metav1.ObjectMeta{Name: name, Namespace: common.OperatorNamespace}))
	if err != nil {
		return nil, fmt.Errorf("failed to watch the manager configmap err=%s", err)
	}
	return watcher, nil
}

func WaitForDeploymentShutdownAndRevokeVaultTokens(ctx context.Context, logger logr.Logger, watcher watch.Interface, client client.Client, clientFactory vault.CachingClientFactory) {
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "Operator manager context canceled")
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if m, ok := event.Object.(*corev1.ConfigMap); ok {
					if val, ok := m.Data[deploymentShutdown]; ok && val == StringTrue {
						clientFactory.Disable()

						// Comment out when running test/integration/revocation_integration_test.go for error path testing.
						// In this case, we can ensure that all tokens in storage are revoked successfully.
						clientFactory.RevokeAllInMemory(ctx)

						if err := setConfigMapInMemoryVaultTokensRevoked(ctx, client); err != nil {
							logger.Error(err, fmt.Sprintf("failed to set %s", deploymentShutdown))
						}
						return
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
		deploymentShutdown: StringTrue,
	})
}

func setConfigMapInMemoryVaultTokensRevoked(ctx context.Context, c client.Client) error {
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
