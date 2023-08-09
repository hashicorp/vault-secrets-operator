// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	ConfigMapSuffix                     = "manager-config"
	ConfigMapKeyShutdown                = "shutdown"
	ConfigMapKeyVaultTokensCleanupModel = "vaultTokensCleanupModel"
	ConfigMapKeyVaultTokensRevoked      = "vaultTokensRevoked"
)

type OnConfigMapChange func(context.Context, *corev1.ConfigMap, client.Client) (bool, error)

func WaitForManagerConfigMapModified(ctx context.Context, watcher watch.Interface, c client.Client, onChanges ...OnConfigMapChange) {
	defer watcher.Stop()
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
						// TODO handle onChange error and executed logic
						if ok, err := onChange(ctx, m, c); err != nil && !ok {
							logger.Error(err, "Failed to execute on configmap change func")
						} else if ok {
							executed[i] = true
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

func IsConfigMapValueTrue(cm *corev1.ConfigMap, key string) (bool, error) {
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

func getConfigMapList(ctx context.Context, c client.Client) (*corev1.ConfigMapList, error) {
	var list corev1.ConfigMapList
	opts := []client.ListOption{
		client.InNamespace(common.OperatorNamespace),
		client.MatchingLabels{"app.kubernetes.io/component": "controller-manager"},
	}

	if err := c.List(ctx, &list, opts...); err != nil {
		return nil, err
	}
	return &list, nil
}

func GetManagerConfigMap(ctx context.Context, c client.Client) (*corev1.ConfigMap, error) {
	list, err := getConfigMapList(ctx, c)
	if err != nil {
		return nil, err
	}

	for _, cm := range list.Items {
		if strings.HasSuffix(cm.Name, ConfigMapSuffix) {
			return &cm, nil
		}
	}
	return nil, fmt.Errorf("the manger configmap suffix=%s not found", ConfigMapSuffix)
}

func WatchManagerConfigMap(ctx context.Context, c client.WithWatch) (watch.Interface, error) {
	list, err := getConfigMapList(ctx, c)
	if err != nil {
		return nil, err
	}

	watcher, err := c.Watch(ctx, list)
	if err != nil {
		return nil, fmt.Errorf("failed to watch the manager configmap err=%s", err)
	}
	return watcher, nil
}

func SetConfigMapShutdown(ctx context.Context, c client.Client, cm *corev1.ConfigMap) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		ConfigMapKeyShutdown: strconv.FormatBool(true),
	}, cm)
}

func SetConfigMapVaultTokensRevoked(ctx context.Context, c client.Client, cm *corev1.ConfigMap) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		ConfigMapKeyVaultTokensRevoked: strconv.FormatBool(true),
	}, cm)
}

func updateManagerConfigMap(ctx context.Context, c client.Client, data map[string]string, cm *corev1.ConfigMap) error {
	for k, v := range data {
		cm.Data[k] = v
	}

	if err := c.Update(ctx, cm, &client.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update the manager configmap data=%v", data)
	}
	return nil
}
