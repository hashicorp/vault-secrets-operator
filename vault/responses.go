// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/vault-secrets-operator/helpers"
)

var (
	_ Response = (*defaultResponse)(nil)
	_ Response = (*kvV2Response)(nil)
	_ Response = (*kvV1Response)(nil)
)

type Response interface {
	Secret() *api.Secret
	Data() map[string]any
	WrapInfo() *api.SecretWrapInfo
	SecretK8sData(*helpers.SecretTransformationOption) (map[string][]byte, error)
}

type defaultResponse struct {
	secret *api.Secret
}

func (r *defaultResponse) WrapInfo() *api.SecretWrapInfo {
	if r.secret != nil {
		return r.secret.WrapInfo
	}
	return nil
}

func (r *defaultResponse) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	var wrapData map[string]any
	if wrapInfo := r.WrapInfo(); wrapInfo != nil {
		b, err := json.Marshal(wrapInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal wrap info: %w", err)
		}
		if err := json.Unmarshal(b, &wrapData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal wrap info: %w", err)
		}
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, wrapData, opt)
}

func (r *defaultResponse) Secret() *api.Secret {
	return r.secret
}

func (r *defaultResponse) Data() map[string]any {
	if r.secret == nil {
		return nil
	}

	return r.secret.Data
}

type kvV1Response struct {
	secret *api.Secret
}

func (r *kvV1Response) WrapInfo() *api.SecretWrapInfo {
	return nil
}

func (r *kvV1Response) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, nil, opt)
}

func (r *kvV1Response) Secret() *api.Secret {
	return r.secret
}

func (r *kvV1Response) Data() map[string]any {
	if r.secret == nil {
		return nil
	}

	return r.secret.Data
}

type kvV2Response struct {
	secret *api.Secret
}

func (r *kvV2Response) WrapInfo() *api.SecretWrapInfo {
	return nil
}

func (r *kvV2Response) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, nil, opt)
}

func (r *kvV2Response) Secret() *api.Secret {
	return r.secret
}

func (r *kvV2Response) Data() map[string]any {
	if r.secret == nil {
		return nil
	}

	if r.secret.Data != nil {
		if v, ok := r.secret.Data["data"]; ok && v != nil {
			if d, ok := v.(map[string]interface{}); ok {
				return d
			}
		}
	}

	return nil
}

func NewKVV1Response(secret *api.Secret) Response {
	return &kvV1Response{
		secret: secret,
	}
}

func NewKVV2Response(secret *api.Secret) Response {
	return &kvV2Response{
		secret: secret,
	}
}

func NewDefaultResponse(secret *api.Secret) Response {
	return &defaultResponse{
		secret: secret,
	}
}

// IsLeaseNotFoundError returns true if a lease not found error is returned from Vault.
func IsLeaseNotFoundError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) && respErr != nil {
		if respErr.StatusCode == http.StatusBadRequest {
			return len(respErr.Errors) == 1 && respErr.Errors[0] == "lease not found"
		}
	}
	return false
}

// IsForbiddenError returns true if a forbidden error is returned from Vault.
func IsForbiddenError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) && respErr != nil {
		if respErr.StatusCode == http.StatusForbidden {
			return true
		}
	}
	return false
}
