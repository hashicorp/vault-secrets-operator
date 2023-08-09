// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Shutdown(ctx context.Context, c client.Client) error {
	cm, err := helpers.GetManagerConfigMap(ctx, c)
	if err != nil {
		return err
	}

	if err := helpers.SetConfigMapShutdown(ctx, c, cm); err != nil {
		return fmt.Errorf("failed to set shutdown in the manager configmap err=%s", err)
	}

	if val, ok := cm.Data[helpers.ConfigMapKeyVaultTokensCleanupModel]; ok &&
		(val == vaultTokensCleanupModelRevoke || val == vaultTokensCleanupModelAll) {
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("shutdown context canceled err=%s", err)
			default:
				time.Sleep(500 * time.Millisecond)
				cm, err = helpers.GetManagerConfigMap(ctx, c)
				if ok, err := helpers.IsConfigMapValueTrue(cm, helpers.ConfigMapKeyVaultTokensRevoked); err != nil {
					return fmt.Errorf("failed to get the configmap value err=%s", err)
				} else if ok {
					return nil
				}
			}
		}
	}
	return nil
}
