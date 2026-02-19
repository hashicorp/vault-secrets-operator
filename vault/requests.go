// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"maps"
	"net/http"
	"net/url"
	"strconv"
)

type BaseRequest interface {
	Path() string
	Headers() http.Header
}

type ReadRequest interface {
	BaseRequest
	Values() url.Values
}

type WriteRequest interface {
	BaseRequest
	Data() map[string]any
}

var (
	_ ReadRequest  = (*kvReadRequestV1)(nil)
	_ ReadRequest  = (*kvReadRequestV2)(nil)
	_ ReadRequest  = (*defaultReadRequest)(nil)
	_ WriteRequest = (*defaultWriteRequest)(nil)
)

type defaultWriteRequest struct {
	path    string
	params  map[string]any
	headers http.Header
	data    []byte
}

func (r *defaultWriteRequest) Headers() http.Header {
	return maps.Clone(r.headers)
}

func (r *defaultWriteRequest) Path() string {
	return r.path
}

func (r *defaultWriteRequest) Data() map[string]any {
	return r.params
}

type defaultReadRequest struct {
	path    string
	values  url.Values
	headers http.Header
}

func (r *defaultReadRequest) Headers() http.Header {
	return maps.Clone(r.headers)
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
	mount   string
	path    string
	headers http.Header
}

func (r *kvReadRequestV1) Headers() http.Header {
	return maps.Clone(r.headers)
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
	headers http.Header
}

func (r *kvReadRequestV2) Headers() http.Header {
	return maps.Clone(r.headers)
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

func NewKVReadRequestV1(mount, path string, headers http.Header) ReadRequest {
	return &kvReadRequestV1{
		mount:   mount,
		path:    path,
		headers: headers,
	}
}

func NewKVReadRequestV2(mount, path string, version int, headers http.Header) ReadRequest {
	return &kvReadRequestV2{
		mount:   mount,
		path:    path,
		headers: headers,
		version: version,
	}
}

func NewReadRequest(path string, values url.Values, headers http.Header) ReadRequest {
	return &defaultReadRequest{
		path:    path,
		values:  values,
		headers: headers,
	}
}

func NewWriteRequest(path string, params map[string]any, headers http.Header) WriteRequest {
	return &defaultWriteRequest{
		path:    path,
		params:  params,
		headers: headers,
	}
}
