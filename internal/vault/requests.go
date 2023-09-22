// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"net/url"
	"strconv"
)

type ReadRequest interface {
	Path() string
	Values() url.Values
}

type WriteRequest interface {
	Path() string
	Params() map[string]any
}

var (
	_ ReadRequest  = (*kvReadRequestV1)(nil)
	_ ReadRequest  = (*kvReadRequestV2)(nil)
	_ ReadRequest  = (*defaultReadRequest)(nil)
	_ WriteRequest = (*defaultWriteRequest)(nil)
)

type defaultWriteRequest struct {
	path   string
	params map[string]any
}

func (r *defaultWriteRequest) Path() string {
	return r.path
}

func (r *defaultWriteRequest) Params() map[string]any {
	return r.params
}

type defaultReadRequest struct {
	path   string
	values url.Values
}

func (r *defaultReadRequest) Path() string {
	return r.path
}

func (r *defaultReadRequest) Values() url.Values {
	return r.values
}

// kvReadRequestV1 can be used in ClientBase.Read to get KV version 1 secrets
// from Vault.
type kvReadRequestV1 struct {
	mount string
	path  string
}

func (r *kvReadRequestV1) Path() string {
	return JoinPath(r.mount, r.path)
}

func (r *kvReadRequestV1) Values() url.Values {
	return nil
}

// kvReadRequestV2 can be used in ClientBase.Read to get KV version 2 secrets
// from Vault.
type kvReadRequestV2 struct {
	mount   string
	path    string
	version int
}

func (r *kvReadRequestV2) Path() string {
	return JoinPath(r.mount, "data", r.path)
}

func (r *kvReadRequestV2) Values() url.Values {
	var vals url.Values
	if r.version > 0 {
		vals = map[string][]string{
			"version": {strconv.Itoa(r.version)},
		}
	}

	return vals
}

func NewKVReadRequestV1(mount, path string) ReadRequest {
	return &kvReadRequestV1{
		mount: mount,
		path:  path,
	}
}

func NewKVReadRequestV2(mount, path string, version int) ReadRequest {
	return &kvReadRequestV2{
		mount:   mount,
		path:    path,
		version: version,
	}
}

func NewReadRequest(path string, values url.Values) ReadRequest {
	return &defaultReadRequest{
		path:   path,
		values: values,
	}
}

func NewWriteRequest(path string, params map[string]any) WriteRequest {
	return &defaultWriteRequest{
		path:   path,
		params: params,
	}
}
