// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

type ShutDownMode int

type ShutDownStatus int

const (
	ShutDownModeUnset ShutDownMode = iota
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
		return "default"
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
	return ShutDownModeUnset
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
// contract
// if the change meets the condition to execute: bool = true
// if the change doesn't meet the condition to execute: return bool = false and error = nil
// if the execution fails: return that bool value and error
func OnShutDown(clientFactory CachingClientFactory) OnConfigMapChange {
	var done bool
	return func(ctx context.Context, cm *corev1.ConfigMap, c client.Client) (bool, error) {
		if done {
			return true, nil
		}

		var err error
		defer func() {
			if err == nil {
				done = true
			}
		}()

		logger := log.FromContext(ctx)
		logger.Info("Starting OnShutDown on configmap change function")
		if !strings.HasSuffix(cm.Name, ConfigMapSuffix) {
			err = fmt.Errorf("modified configmap is not the manager configmap")
			return false, err
		}

		mode := getShutDownMode(cm)
		var shutdownReq CachingClientFactoryShutDownRequest
		switch mode {
		case ShutDownModeNoPreserve:
			shutdownReq.Preserve = false
		case ShutDownModePreserve:
			shutdownReq.Preserve = true
		case ShutDownModeUnset:
			err = fmt.Errorf("%s is not set", ConfigMapKeyShutDownMode)
			return false, err
		}

		var errs error
		errs = errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusPending))
		if shutDownErr := errors.Join(clientFactory.ShutDown(shutdownReq)); shutDownErr != nil {
			errs = errors.Join(shutDownErr)
			errs = errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusFailed))
		} else {
			errs = errors.Join(SetShutDownStatus(ctx, c, cm, ShutDownStatusDone))
		}
		err = errs
		return true, errs
	}
}
