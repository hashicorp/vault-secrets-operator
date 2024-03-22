// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package consts

import v1 "k8s.io/api/core/v1"

const (
	NameDefault = "default"

	KVSecretTypeV2 = "kv-v2"
	KVSecretTypeV1 = "kv-v1"

	// TLSSecretCAKey used to access the CA certificates from a TLS K8s Secret.
	// Alias to v1.ServiceAccountRootCAKey, since that seems to be only API
	// constant that shares the expected key name.
	TLSSecretCAKey = v1.ServiceAccountRootCAKey

	AWSAccessKeyID     = "access_key_id"
	AWSSecretAccessKey = "secret_access_key"
	AWSRoleARN         = "role_arn"
	AWSSessionName     = "session_name"
	AWSSessionToken    = "session_token"

	AnnotationResync = "vso.hashicorp.com/resync"
)
