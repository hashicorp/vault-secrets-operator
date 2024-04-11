// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

var (
	_ Response = (*defaultResponse)(nil)
	_ Response = (*kvV2Response)(nil)
)

type Response interface {
	Secret() *api.Secret
	Data() map[string]any
	SecretK8sData(*helpers.SecretTransformationOption) (map[string][]byte, error)
}

type defaultResponse struct {
	secret *api.Secret
}

func (r *defaultResponse) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, opt)
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

func (r *kvV1Response) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, opt)
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

func (r *kvV2Response) SecretK8sData(opt *helpers.SecretTransformationOption) (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return helpers.NewSecretsDataBuilder().WithVaultData(r.Data(), rawData, opt)
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

func IsLeaseNotFoundError(err error) bool {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) && respErr != nil {
		if respErr.StatusCode == http.StatusBadRequest {
			return len(respErr.Errors) == 1 && respErr.Errors[0] == "lease not found"
		}
	}
	return false
}
