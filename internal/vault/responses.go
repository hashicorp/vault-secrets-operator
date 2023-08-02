// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import "github.com/hashicorp/vault/api"

var (
	_ Response = (*defaultResponse)(nil)
	_ Response = (*kvV2Response)(nil)
)

type Response interface {
	Secret() *api.Secret
	Data() map[string]interface{}
}

type defaultResponse struct {
	secret *api.Secret
}

func (r *defaultResponse) Secret() *api.Secret {
	return r.secret
}

func (r *defaultResponse) Data() map[string]interface{} {
	if r.secret == nil {
		return nil
		// return make(map[string]interface{}, 0)
	}

	return r.secret.Data
}

type kvV2Response struct {
	secret *api.Secret
}

func (r *kvV2Response) Secret() *api.Secret {
	return r.secret
}

func (r *kvV2Response) Data() map[string]interface{} {
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

func NewKVV2Response(secret *api.Secret) Response {
	return &kvV2Response{
		secret: secret,
	}
}

func NewResponse(secret *api.Secret) Response {
	return &defaultResponse{
		secret: secret,
	}
}
