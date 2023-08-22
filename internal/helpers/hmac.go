// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

// HandleSecretHMAC compares the HMAC of data to its previously computed value
// stored in o.Status.SecretHMAC, returning true if they are equal. The computed
// new-MAC will be returned so that o.Status.SecretHMAC can be updated.
//
// Supported types for obj are: VaultDynamicSecret, VaultStaticSecret
func HandleSecretHMAC(ctx context.Context, client ctrlclient.Client,
	validator vault.HMACValidator, obj ctrlclient.Object, data map[string][]byte,
) (bool, []byte, error) {
	var cur string
	switch t := obj.(type) {
	case *v1beta1.VaultDynamicSecret:
		cur = t.Status.SecretMAC
	case *v1beta1.VaultStaticSecret:
		cur = t.Status.SecretMAC
	default:
		return false, nil, fmt.Errorf("unsupported object type %T", t)
	}
	logger := log.FromContext(ctx)

	// HMAC the Vault secret data so that it can be compared to the what's in the
	// destination Secret.
	message, err := json.Marshal(data)
	if err != nil {
		return false, nil, err
	}

	newMAC, err := validator.HMAC(ctx, client, message)
	if err != nil {
		return false, nil, err
	}

	// we have never computed the Vault secret data HMAC,
	// so there is no need to perform Secret data drift detection.
	if cur == "" {
		return false, newMAC, nil
	}

	lastMAC, err := base64.StdEncoding.DecodeString(cur)
	if err != nil {
		return false, nil, err
	}

	macsEqual := vault.EqualMACS(lastMAC, newMAC)
	if macsEqual {
		// check to see if the Secret.Data has drifted since the last sync, if it has
		// then it will be overwritten with the Vault secret data this would indicate an
		// out-of-band change made to the Secret's data in this case the controller
		// should do the sync.
		if cur, ok, _ := GetSecret(ctx, client, obj); ok {
			curMessage, err := json.Marshal(cur.Data)
			if err != nil {
				return false, nil, err
			}

			logger.V(consts.LogLevelDebug).Info(
				"Doing Secret data drift detection", "lastMAC", lastMAC)
			// we only care of the MAC has changed, it's new value is not important here.
			valid, foundMAC, err := validator.Validate(ctx, client, curMessage, lastMAC)
			if err != nil {
				return false, nil, err
			}
			if !valid {
				logger.V(consts.LogLevelDebug).Info("Secret data drift detected",
					"lastMAC", lastMAC, "foundMAC", foundMAC,
					"curMessage", curMessage, "message", message)
			}

			macsEqual = valid
		} else {
			// assume MACs are not equal if the secret does not exist or an error (ignored)
			// has occurred
			macsEqual = false
		}
	}

	return macsEqual, newMAC, nil
}
