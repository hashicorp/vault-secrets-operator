// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	DeploymentStatusConfigMapName             = "deploymentstatus"
	DeploymentStatusDeletionTimestampReceived = "deletion_timestamp_received"
	DeploymentStatusManagerAcked              = "manager_acked"
	StringTrue                                = "true"
	StringFalse                               = "false"
)

type deploymentStatus map[string]string

func CreateDeploymentStatusConfigMap(ctx context.Context, c client.Client) error {
	status := deploymentStatus{
		DeploymentStatusDeletionTimestampReceived: StringFalse,
		DeploymentStatusManagerAcked:              StringFalse,
	}

	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentStatusConfigMapName,
			Namespace: common.OperatorNamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: common.OperatorDeploymentAPIVersion,
					Kind:       common.OperatorDeploymentKind,
					Name:       common.OperatorDeploymentName,
					UID:        common.OperatorDeploymentUID,
				},
			},
		},
		Data: status,
	}
	if err := c.Create(ctx, &configMap); err != nil {
		return err
	}

	return nil
}

func AwaitManagerAcked(ctx context.Context, logger logr.Logger, c client.Client) {
	var (
		configMap corev1.ConfigMap
		key       = getDeploymentStatusConfigMapKey()
	)

	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "failed to await manager acked")
			return
		default:
			if err := c.Get(ctx, key, &configMap); err != nil {
				logger.Error(err, "failed to get configmap", "name", DeploymentStatusConfigMapName)
			} else if value, ok := configMap.Data[DeploymentStatusManagerAcked]; ok && value == StringTrue {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func AwaitDeletionTimestampReceived(ctx context.Context, logger logr.Logger, c client.Client) {
	var (
		configMap corev1.ConfigMap
		key       = getDeploymentStatusConfigMapKey()
	)

	logger = logger.WithValues("configMap", DeploymentStatusConfigMapName)
	for {
		select {
		case <-ctx.Done():
			logger.Error(ctx.Err(), "failed to await deletion timestamp received")
			return
		default:

			if err := c.Get(ctx, key, &configMap); err != nil {
				logger.Error(err, "failed to get object")
			} else if value, ok := configMap.Data[DeploymentStatusDeletionTimestampReceived]; ok && value == StringTrue {
				if err = setManagerAcked(ctx, c); err != nil {
					logger.Error(err, "failed to set manager acked")
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func setManagerAcked(ctx context.Context, c client.Client) error {
	return updateDeploymentStatusConfigMap(ctx, c, deploymentStatus{
		DeploymentStatusDeletionTimestampReceived: StringTrue,
		DeploymentStatusManagerAcked:              StringTrue,
	})
}

func SetDeletionTimestampReceived(ctx context.Context, c client.Client) error {
	return updateDeploymentStatusConfigMap(ctx, c, deploymentStatus{
		DeploymentStatusDeletionTimestampReceived: StringTrue,
		DeploymentStatusManagerAcked:              StringFalse,
	})
}

func updateDeploymentStatusConfigMap(ctx context.Context, c client.Client, data map[string]string) error {
	var configMap corev1.ConfigMap
	err := c.Get(ctx, getDeploymentStatusConfigMapKey(), &configMap)
	if err != nil {
		return err
	}

	configMap.Data = data

	if err = c.Update(ctx, &configMap, &client.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

func getDeploymentStatusConfigMapKey() client.ObjectKey {
	return client.ObjectKey{
		Name:      DeploymentStatusConfigMapName,
		Namespace: common.OperatorNamespace,
	}
}
