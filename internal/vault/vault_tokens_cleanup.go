// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	vaultTokensCleanupModelRevoke = "revoke"
	vaultTokensCleanupModelPrune  = "prune"
	vaultTokensCleanupModelAll    = "all"
)

func OnShutdown(clientFactory CachingClientFactory) helpers.OnConfigMapChange {
	//var done bool
	return func(ctx context.Context, cm *corev1.ConfigMap, c client.Client) (bool, error) {
		//if done {
		//	return true, nil
		//}
		logger := log.FromContext(ctx)
		logger.Info("Starting OnShutdown on configmap change function")
		if ok, err := helpers.IsConfigMapValueTrue(cm, helpers.ConfigMapKeyShutdown); err != nil {
			return false, err
		} else if !ok {
			return false, nil
		}

		model, _ := cm.Data[helpers.ConfigMapKeyVaultTokensCleanupModel]
		if model == "" {
			logger.Info("Skipping Vault tokens cleanup", "model", model)
			return true, nil
		}

		logger.Info("Cleaning up Vault tokens", "model", model)
		shutdownReq := CachingClientFactoryShutdownRequest{
			Revoke: model == vaultTokensCleanupModelRevoke || model == vaultTokensCleanupModelAll,
			Prune:  model == vaultTokensCleanupModelPrune || model == vaultTokensCleanupModelAll,
		}
		clientFactory.Shutdown(ctx, c, shutdownReq)

		//done = true
		return true, helpers.SetConfigMapVaultTokensRevoked(ctx, c, cm)
	}
}

func GetStorageOwnerRefs(ctx context.Context, c client.Client) ([]metav1.OwnerReference, error) {
	model, err := getVaultTokensCleanupModel(ctx, c)
	if err != nil {
		return nil, err
	}

	fmt.Println("model", model)
	if model != vaultTokensCleanupModelPrune && model != vaultTokensCleanupModelAll {
		return nil, nil
	}

	dep, err := getOperatorDeployment(ctx, c)
	if err != nil {
		return nil, err
	}

	fmt.Println(dep)
	ownerRef, err := helpers.GetOwnerRefFromObj(dep, c.Scheme())
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
	cm, err := helpers.GetManagerConfigMap(ctx, c)
	if err != nil {
		return "", err
	}
	val, ok := cm.Data[helpers.ConfigMapKeyVaultTokensCleanupModel]
	if !ok {
		return "", fmt.Errorf("key=%s doesn't exists in the manager configmap", helpers.ConfigMapKeyVaultTokensCleanupModel)
	}
	return val, nil
}
