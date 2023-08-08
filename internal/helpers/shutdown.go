// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"time"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	envVarManagerConfigMapName = "MANAGER_CONFIGMAP_NAME"
	errMsgGetManagerConfigMap  = "failed to get the manager configmap"
)

func Shutdown(ctx context.Context, c client.Client) {
	logger := log.FromContext(ctx)

	if err := setConfigMapShutdown(ctx, c); err != nil {
		logger.Error(err, "Failed to set shutdown in the manager configmap")
	}

	name := getManagerConfigMapName()
	if name == "" {
		logger.Error(nil, "failed to parse the manager configmap name", "env", envVarManagerConfigMapName)
	}

	objKey := client.ObjectKey{Namespace: common.OperatorNamespace, Name: name}
	cm, err := getManagerConfigMap(ctx, c, objKey)
	if err != nil {
		logger.Error(err, errMsgGetManagerConfigMap)
	}

	if val, ok := cm.Data[configMapKeyVaultTokensCleanupModel]; ok &&
		(val == vaultTokensCleanupModelRevoke || val == vaultTokensCleanupModelAll) {
		for {
			select {
			case <-ctx.Done():
				logger.Error(err, "Shutdown context canceled")
				return
			default:
				time.Sleep(300 * time.Millisecond)
				cm, err = getManagerConfigMap(ctx, c, objKey)
				if ok, err := isConfigMapValueTrue(cm, configMapKeyVaultTokensRevoked); err != nil {
					logger.Error(err, "Failed to get the configmap value")
				} else if ok {
					return
				}
			}
		}
	}
	return
}
