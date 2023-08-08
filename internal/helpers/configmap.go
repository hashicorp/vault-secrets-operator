// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	configMapKeyShutdown                = "shutdown"
	configMapKeyVaultTokensCleanupModel = "vaultTokensCleanupModel"
	configMapKeyVaultTokensRevoked      = "vaultTokensRevoked"
)

type onConfigMapChange func(context.Context, *corev1.ConfigMap, client.Client) (bool, error)

func waitForManagerConfigMapModified(ctx context.Context, watcher watch.Interface, c client.Client, onChanges ...onConfigMapChange) {
	logger := log.FromContext(ctx)
	executed := make([]bool, len(onChanges))
	executedCnt := 0
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "Operator manager context canceled")
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if m, ok := event.Object.(*corev1.ConfigMap); ok {
					for i, onChange := range onChanges {
						if executed[i] {
							continue
						}
						if ok, err := onChange(ctx, m, c); err != nil {
							logger.Error(err, "Failed to execute on configmap change func")
						} else if ok {
							executedCnt += 1
						}
					}
					if executedCnt == len(onChanges) {
						return
					}
				}
			}
		}
	}
}

func isConfigMapValueTrue(cm *corev1.ConfigMap, key string) (bool, error) {
	s, ok := cm.Data[key]
	if !ok {
		return false, fmt.Errorf("key=%s doesn't exist in the configmap", key)
	}
	val, err := strconv.ParseBool(s)
	if err != nil {
		return false, err
	}
	return val, nil
}

func getManagerConfigMapName() string {
	return os.Getenv(envVarManagerConfigMapName)
}

func getManagerConfigMap(ctx context.Context, c client.Client, objKey client.ObjectKey) (*corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	err := c.Get(ctx, objKey, &cm)
	if err != nil {
		return nil, err
	}
	return &cm, nil
}

func watchManagerConfigMap(ctx context.Context, c client.WithWatch) (watch.Interface, error) {
	name := getManagerConfigMapName()
	if name == "" {
		return nil, fmt.Errorf("failed to parse the manager configmap name from %s", envVarManagerConfigMapName)
	}

	cm, err := getManagerConfigMap(ctx, c, client.ObjectKey{Namespace: common.OperatorNamespace, Name: name})
	if err != nil {
		return nil, fmt.Errorf(errMsgGetManagerConfigMap+" err=%s", err)
	}

	list := corev1.ConfigMapList{Items: []corev1.ConfigMap{*cm}}
	watcher, err := c.Watch(ctx, &list)
	if err != nil {
		return nil, fmt.Errorf("failed to watch the manager configmap err=%s", err)
	}
	return watcher, nil
}

func setConfigMapShutdown(ctx context.Context, c client.Client) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		configMapKeyShutdown: strconv.FormatBool(true),
	})
}

func setConfigMapVaultTokensRevoked(ctx context.Context, c client.Client) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		configMapKeyVaultTokensRevoked: strconv.FormatBool(true),
	})
}

func updateManagerConfigMap(ctx context.Context, c client.Client, data map[string]string) error {
	name := getManagerConfigMapName()
	if name == "" {
		return fmt.Errorf("failed to parse manager configmap name from %s", envVarManagerConfigMapName)
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
