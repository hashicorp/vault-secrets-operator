// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

type ShutDownMode int

type ShutDownStatus int

const (
	ShutDownModeUnknown ShutDownMode = iota
	ShutDownModePreserve
	ShutDownModeNoPreserve
	ConfigMapSuffix = "manager-config"

	ConfigMapKeyShutDownMode   = "shutDownMode"
	ConfigMapKeyShutDownStatus = "shutDownStatus"

	ShutDownStatusDone ShutDownStatus = iota
	ShutDownStatusFailed
	ShutDownStatusPending
	ShutDownStatusUnknown
)

func (m ShutDownMode) String() string {
	switch m {
	case ShutDownModePreserve:
		return "preserve"
	case ShutDownModeNoPreserve:
		return "no-preserve"
	default:
		return "unknown"
	}
}

func (s ShutDownStatus) String() string {
	switch s {
	case ShutDownStatusPending:
		return "pending"
	case ShutDownStatusFailed:
		return "failed"
	case ShutDownStatusDone:
		return "done"
	default:
		return "unknown"
	}
}

type OnConfigMapChange func(context.Context, client.Client, *corev1.ConfigMap)

func WaitForManagerConfigMapModified(ctx context.Context, watcher watch.Interface, c client.Client, onChanges ...OnConfigMapChange) {
	defer watcher.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-watcher.ResultChan():
			if event.Type == watch.Modified {
				if cm, ok := event.Object.(*corev1.ConfigMap); ok {
					for _, onChange := range onChanges {
						onChange(ctx, c, cm)
					}
				}
			}
		}
	}
}

// getManagerConfigMapList returns the manager configmap list that has configmaps with labels matching
// "app.kubernetes.io/component": "controller-manager". For simplicity, we assume there should be one manager configmap
func getManagerConfigMapList(ctx context.Context, c client.Client) (*corev1.ConfigMapList, error) {
	labels := client.MatchingLabels{"app.kubernetes.io/component": "controller-manager"}
	opts := []client.ListOption{
		client.InNamespace(common.OperatorNamespace),
		labels,
	}

	var list corev1.ConfigMapList
	if err := c.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no configmaps matching labels=%v found in the operator namespace", labels)
	}

	if len(list.Items) > 1 {
		return nil, fmt.Errorf("more than 1 configmaps matching labels=%v found in the operator namespace", labels)
	}

	return &list, nil
}

func GetManagerConfigMap(ctx context.Context, c client.Client) (*corev1.ConfigMap, error) {
	list, err := getManagerConfigMapList(ctx, c)
	if err != nil {
		return nil, err
	}

	return &list.Items[0], err
}

func WatchManagerConfigMap(ctx context.Context, c client.WithWatch) (watch.Interface, error) {
	list, err := getManagerConfigMapList(ctx, c)
	if err != nil {
		return nil, err
	}

	watcher, err := c.Watch(ctx, list)
	if err != nil {
		return nil, fmt.Errorf("failed to watch the manager configmap err=%s", err)
	}
	return watcher, nil
}

func SetShutDownStatus(ctx context.Context, c client.Client, cm *corev1.ConfigMap, status ShutDownStatus) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		ConfigMapKeyShutDownStatus: status.String(),
	}, cm)
}

func SetShutDownMode(ctx context.Context, c client.Client, cm *corev1.ConfigMap, mode ShutDownMode) error {
	return updateManagerConfigMap(ctx, c, map[string]string{
		ConfigMapKeyShutDownMode: mode.String(),
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

func getShutDownMode(cm *corev1.ConfigMap) ShutDownMode {
	mode := cm.Data[ConfigMapKeyShutDownMode]
	if mode == ShutDownModeNoPreserve.String() {
		return ShutDownModeNoPreserve
	}
	if mode == ShutDownModePreserve.String() {
		return ShutDownModePreserve
	}
	return ShutDownModeUnknown
}

func GetShutDownStatus(cm *corev1.ConfigMap) ShutDownStatus {
	status := cm.Data[ConfigMapKeyShutDownStatus]
	switch status {
	case ShutDownStatusDone.String():
		return ShutDownStatusDone
	case ShutDownStatusFailed.String():
		return ShutDownStatusFailed
	case ShutDownStatusPending.String():
		return ShutDownStatusPending
	default:
		return ShutDownStatusUnknown
	}
}

// OnShutDown shuts down the client factory if the manager configmap's ConfigMapKeyShutDownMode is set, and
// sets ConfigMapKeyShutDownStatus based on the client factory shutdown error
func OnShutDown(clientFactory CachingClientFactory) OnConfigMapChange {
	var completed bool
	return func(ctx context.Context, c client.Client, cm *corev1.ConfigMap) {
		if completed {
			return
		}
		logger := log.FromContext(ctx)

		mode := getShutDownMode(cm)
		var shutdownReq CachingClientFactoryShutDownRequest
		switch mode {
		case ShutDownModeNoPreserve:
			shutdownReq.Preserve = false
		case ShutDownModePreserve:
			shutdownReq.Preserve = true
		case ShutDownModeUnknown:
			return
		}

		errs := errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusPending))
		if err := errors.Join(clientFactory.ShutDown(shutdownReq)); err != nil {
			errs = errors.Join(err)
			errs = errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusFailed))
		} else {
			errs = errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusDone))
		}
		if errs != nil {
			logger.Error(errs, "OnShutDown failed")
		} else {
			completed = true
		}
		return
	}
}
