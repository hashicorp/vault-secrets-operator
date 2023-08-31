// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

var (
	_ Response = (*defaultResponse)(nil)
	_ Response = (*kvV2Response)(nil)
)

type Response interface {
	Secret() *api.Secret
	Data() map[string]any
	SecretK8sData() (map[string][]byte, error)
}

type defaultResponse struct {
	secret *api.Secret
}

func (r *defaultResponse) SecretK8sData() (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	return MakeSecretK8sData(r.Data(), rawData)
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

func (r *kvV1Response) SecretK8sData() (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return MakeSecretK8sData(r.Data(), rawData)
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

func (r *kvV2Response) SecretK8sData() (map[string][]byte, error) {
	var rawData map[string]interface{}
	if r.secret != nil {
		rawData = r.secret.Data
	}

	if rawData == nil {
		return nil, fmt.Errorf("raw portion of vault KV secret was nil")
	}

	return MakeSecretK8sData(r.Data(), rawData)
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
