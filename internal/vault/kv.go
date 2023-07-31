// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"net/url"
	"strconv"
)

type KVReadRequest interface {
	Path() string
	Values() url.Values
}

var (
	_ KVReadRequest = (*KVReadRequestV1)(nil)
	_ KVReadRequest = (*KVReadRequestV2)(nil)
)

// KVReadRequestV1 can be used in ClientBase.ReadKV to get KV version 1 secrets
// from Vault.
type KVReadRequestV1 struct {
	mount string
	path  string
}

func (r *KVReadRequestV1) Path() string {
	return JoinPath(r.mount, r.path)
}

func (r *KVReadRequestV1) Values() url.Values {
	return nil
}

// KVReadRequestV2 can be used in ClientBase.ReadKV to get KV version 2 secrets
// from Vault.
type KVReadRequestV2 struct {
	mount   string
	path    string
	version int
}

func (r *KVReadRequestV2) Path() string {
	return JoinPath(r.mount, "data", r.path)
}

func (r *KVReadRequestV2) Values() url.Values {
	var vals url.Values
	if r.version > 0 {
		vals = map[string][]string{
			"version": {strconv.Itoa(r.version)},
		}
	}

	return vals
}

func NewKVSecretRequestV1(mount, path string) *KVReadRequestV1 {
	return &KVReadRequestV1{
		mount: mount,
		path:  path,
	}
}

func NewKVSecretRequestV2(mount, path string, version int) *KVReadRequestV2 {
	return &KVReadRequestV2{
		mount:   mount,
		path:    path,
		version: version,
	}
}
