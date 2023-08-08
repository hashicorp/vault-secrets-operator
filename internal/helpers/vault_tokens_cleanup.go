// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
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

func AwaitForManagerConfigMapModified(ctx context.Context, c client.WithWatch, clientFactory vault.CachingClientFactory) {
	logger := log.FromContext(ctx)
	watcher, err := watchManagerConfigMap(ctx, c)
	if err != nil {
		logger.Error(err, "Failed to setup the manager ConfigMap watcher")
		os.Exit(1)
	}

	go waitForManagerConfigMapModified(ctx, watcher, c, onShutdown(clientFactory))
}

func onShutdown(clientFactory vault.CachingClientFactory) onConfigMapChange {
	return func(ctx context.Context, cm *corev1.ConfigMap, c client.Client) (bool, error) {
		logger := log.FromContext(ctx)
		logger.Info("Starting onShutdown on configmap change function")
		if ok, err := isConfigMapValueTrue(cm, configMapKeyShutdown); err != nil {
			return false, err
		} else if !ok {
			return false, nil
		}

		model, err := getVaultTokensCleanupModel(ctx, c)
		if err != nil {
			return true, fmt.Errorf("failed to get Vault tokens cleanup model err=%s", err)
		}
		if model != vaultTokensCleanupModelAll && model != vaultTokensCleanupModelRevoke {
			logger.Info("Skipping Vault tokens cleanup", "model", model)
			return true, nil
		}

		logger.Info("Cleaning up Vault tokens", "model", model)

		clientFactory.Disable()

		// Comment out when running test/integration/revocation_integration_test.go for error path testing.
		// In this case, we can ensure that all tokens in storage are revoked successfully.
		clientFactory.RevokeAllInMemory(ctx)

		// Comment out when running test/integration/revocation_integration_test.go for error path testing.
		// In this case, we can ensure that all tokens cached in memory are revoked successfully.
		clientFactory.RevokeAllInStorage(ctx, c)

		return true, setConfigMapVaultTokensRevoked(ctx, c)
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
	ownerRef, err := GetOwnerRefFromObj(dep, c.Scheme())
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
	name := getManagerConfigMapName()
	if name == "" {
		return "", fmt.Errorf("failed to parse the manager configmap name env=%s", envVarManagerConfigMapName)
	}
	objKey := client.ObjectKey{Namespace: common.OperatorNamespace, Name: name}
	cm, err := getManagerConfigMap(ctx, c, objKey)
	if err != nil {
		return "", fmt.Errorf(errMsgGetManagerConfigMap+" err=%s", err)
	}
	val, ok := cm.Data[configMapKeyVaultTokensCleanupModel]
	if !ok {
		return "", fmt.Errorf("key=%s doesn't exists in the manager configmap", configMapKeyVaultTokensCleanupModel)
	}
	return val, nil
}
