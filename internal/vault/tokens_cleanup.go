// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/utils"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	VaultTokensCleanupModelRevoke = "revoke"
	VaultTokensCleanupModelPrune  = "prune"
	VaultTokensCleanupModelAll    = "all"
)

// TODO
// contract
// if the change meets the condition to execute: bool = true
// if the change doesn't meet the condition to execute: return bool = false and error = nil
// if the execution fails: return that bool value and error
func OnShutdown(clientFactory CachingClientFactory) OnConfigMapChange {
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
		logger.Info("Starting OnShutdown on configmap change function")
		if !strings.HasSuffix(cm.Name, ConfigMapSuffix) {
			err = fmt.Errorf("modified config is not the manager configmap")
			return false, err
		}

		var ok bool
		if ok, err = IsConfigMapValueTrue(cm, ConfigMapKeyShutdown); err != nil {
			return false, err
		} else if !ok {
			err = fmt.Errorf("shutdown is false")
			return false, err
		}

		model, _ := cm.Data[ConfigMapKeyVaultTokensCleanupModel]
		if model == "" {
			logger.Info("Skipping Vault tokens cleanup", "model", model)
			return true, nil
		}

		logger.Info("Cleaning up Vault tokens", "model", model)
		shutdownReq := CachingClientFactoryShutdownRequest{
			Revoke: model == VaultTokensCleanupModelRevoke || model == VaultTokensCleanupModelAll,
			Prune:  model == VaultTokensCleanupModelPrune || model == VaultTokensCleanupModelAll,
		}

		err = clientFactory.Shutdown(ctx, c, shutdownReq)
		if err != nil {
			return true, err
		}
		return true, SetConfigMapVaultTokensRevoked(ctx, c, cm)
	}
}

func GetStorageOwnerRefs(ctx context.Context, c client.Client) ([]metav1.OwnerReference, error) {
	model, err := getVaultTokensCleanupModel(ctx, c)
	if err != nil {
		return nil, err
	}

	fmt.Println("model", model)
	if model != VaultTokensCleanupModelPrune && model != VaultTokensCleanupModelAll {
		return nil, nil
	}

	dep, err := getOperatorDeployment(ctx, c)
	if err != nil {
		return nil, err
	}

	fmt.Println(dep)
	ownerRef, err := utils.GetOwnerRefFromObj(dep, c.Scheme())
	if err != nil {
		return nil, err
	}
	return []metav1.OwnerReference{ownerRef}, nil
}

func getOperatorDeployment(ctx context.Context, c client.Client) (*v1.Deployment, error) {
	deps := &v1.DeploymentList{}
	opts := []client.ListOption{
		client.InNamespace(common.OperatorNamespace),
		client.MatchingLabels{
			"control-plane": "controller-manager",
		},
	}
	if err := c.List(ctx, deps, opts...); err != nil {
		return nil, err
	}

	if len(deps.Items) != 1 {
		return nil, fmt.Errorf("found more than one deployment in the operator namespace")
	}
	return &deps.Items[0], nil
}

func getVaultTokensCleanupModel(ctx context.Context, c client.Client) (string, error) {
	cm, err := GetManagerConfigMap(ctx, c)
	if err != nil {
		return "", err
	}
	val, ok := cm.Data[ConfigMapKeyVaultTokensCleanupModel]
	if !ok {
		return "", fmt.Errorf("key=%s doesn't exists in the manager configmap", ConfigMapKeyVaultTokensCleanupModel)
	}
	return val, nil
}
