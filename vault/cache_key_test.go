// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/credentials/vault/consts"
)

const (
	authUID       = types.UID("c4fad6b9-e7bb-4ed8-bc38-67fd6dc85a35")
	connUID       = types.UID("c4fad6b9-e7bb-4ed8-bc38-67fd6dc85a36")
	providerUID   = types.UID("c4fad6b9-e7bb-4ed8-bc38-67fd6dc85a37")
	computedHash  = "2a8108711ae49ac0faa724"
	computedHash2 = "2a8108711ae49ac0faa725"
)

type computeClientCacheKeyTest struct {
	name        string
	authObj     *secretsv1beta1.VaultAuth
	connObj     *secretsv1beta1.VaultConnection
	providerUID types.UID
	want        ClientCacheKey
	wantErr     assert.ErrorAssertionFunc
}

func Test_computeClientCacheKey(t *testing.T) {
	t.Parallel()
	tests := []computeClientCacheKeyTest{
		{
			name: "valid",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        connUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			want:        "ical-" + computedHash,
			wantErr:     assert.NoError,
		},
		{
			name: "valid-key-at-max-length",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical" + strings.Repeat("x", 36),
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        connUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			want:        ClientCacheKey("ical" + strings.Repeat("x", 36) + "-" + computedHash),
			wantErr:     assert.NoError,
		},
		{
			name: "valid-mixed-case-method-name",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "icalBarBaz",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        connUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			want:        ClientCacheKey("icalbarbaz" + "-" + computedHash),
			wantErr:     assert.NoError,
		},
		{
			name: "invalid-key-max-length-exceeded",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical" + strings.Repeat("x", 37),
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        connUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return !assert.ErrorIs(t, err, errorKeyLengthExceeded, i...)
			},
		},
		{
			name: "invalid-duplicate-uid",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return !assert.ErrorIs(t, err, errorDuplicateUID, i...)
			},
		},
		{
			name: "invalid-uid-length-above",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID + "1",
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return !assert.ErrorIs(t, err, errorInvalidUIDLength, i...)
			},
		},
		{
			name: "invalid-uid-length-below",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID[0 : len(authUID)-1],
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return !assert.ErrorIs(t, err, errorInvalidUIDLength, i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeClientCacheKey(tt.authObj, tt.connObj, tt.providerUID, false)
			if !tt.wantErr(t, err, fmt.Sprintf("computeClientCacheKey(%v, %v, %v, false)",
				tt.authObj, tt.connObj, tt.providerUID)) {
				return
			}
			assert.Equalf(t, tt.want, got, "computeClientCacheKey(%v, %v, %v, false)", tt.authObj, tt.connObj, tt.providerUID)
		})
	}
}

func Test_computeClientCacheKey_standalone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		authObj     *secretsv1beta1.VaultAuth
		connObj     *secretsv1beta1.VaultConnection
		providerUID types.UID
		wantErr     assert.ErrorAssertionFunc
		wantPrefix  string // expected method prefix in cache key
	}{
		{
			name: "standalone-empty-provideruid-fails",
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: consts.ProviderMethodAppRole,
				},
			},
			connObj:     &secretsv1beta1.VaultConnection{},
			providerUID: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Error(t, err, i...)
			},
		},
		{
			name: "standalone-different-auth-specs-different-keys",
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: consts.ProviderMethodAppRole,
					AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
						RoleID: "role-1",
					},
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				Spec: secretsv1beta1.VaultConnectionSpec{
					Address: "http://vault:8200",
				},
			},
			providerUID: providerUID,
			wantErr:     assert.NoError,
			wantPrefix:  "approle-",
		},
		{
			name: "standalone-different-conn-specs-different-keys",
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: consts.ProviderMethodJWT,
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				Spec: secretsv1beta1.VaultConnectionSpec{
					Address: "http://vault:9200",
				},
			},
			providerUID: providerUID,
			wantErr:     assert.NoError,
			wantPrefix:  "jwt-",
		},
		{
			name: "standalone-empty-method-fails",
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{},
			},
			providerUID: providerUID,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Error(t, err, i...)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeClientCacheKey(tt.authObj, tt.connObj, tt.providerUID, true)
			if !tt.wantErr(t, err, fmt.Sprintf("computeClientCacheKey(%v, %v, %v, true)",
				tt.authObj, tt.connObj, tt.providerUID)) {
				return
			}
			if tt.wantPrefix != "" {
				assert.True(t, strings.HasPrefix(got.String(), tt.wantPrefix),
					"expected key to start with %q, got %q", tt.wantPrefix, got.String())
			}
		})
	}
}

// Test that standalone mode produces deterministic, content-based cache keys
func Test_computeClientCacheKey_standalone_deterministic(t *testing.T) {
	t.Parallel()

	authObj := &secretsv1beta1.VaultAuth{
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: consts.ProviderMethodAppRole,
			AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
				RoleID: "test-role",
			},
		},
	}
	connObj := &secretsv1beta1.VaultConnection{
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: "http://vault:8200",
		},
	}

	// Call twice with identical inputs
	key1, err1 := computeClientCacheKey(authObj, connObj, providerUID, true)
	require.NoError(t, err1)

	key2, err2 := computeClientCacheKey(authObj, connObj, providerUID, true)
	require.NoError(t, err2)

	// Should produce identical cache keys
	assert.Equal(t, key1, key2, "identical specs should produce identical cache keys")
}

// Test that standalone and normal mode produce different cache keys
func Test_computeClientCacheKey_standalone_vs_normal(t *testing.T) {
	t.Parallel()

	authObjWithUID := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			UID:        authUID,
			Generation: 1,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: consts.ProviderMethodAppRole,
			AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
				RoleID: "test-role",
			},
		},
	}
	connObjWithUID := &secretsv1beta1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			UID:        connUID,
			Generation: 2,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: "http://vault:8200",
		},
	}

	authObjNoUID := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{
			UID:        "",
			Generation: 0,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: consts.ProviderMethodAppRole,
			AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
				RoleID: "test-role",
			},
		},
	}
	connObjNoUID := &secretsv1beta1.VaultConnection{
		ObjectMeta: metav1.ObjectMeta{
			UID:        "",
			Generation: 0,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: "http://vault:8200",
		},
	}

	// Normal mode with UIDs - should succeed
	normalKey, err := computeClientCacheKey(authObjWithUID, connObjWithUID, providerUID, false)
	require.NoError(t, err)

	// Standalone mode without UIDs - should succeed
	standaloneKey, err := computeClientCacheKey(authObjNoUID, connObjNoUID, providerUID, true)
	require.NoError(t, err)

	// Keys should be different because:
	// - Normal mode uses UID + generation
	// - Standalone mode uses spec hash + generation=1
	assert.NotEqual(t, normalKey, standaloneKey,
		"standalone and normal mode should produce different cache keys even with same specs")

	assert.True(t, strings.HasPrefix(normalKey.String(), "approle-"))
	assert.True(t, strings.HasPrefix(standaloneKey.String(), "approle-"))

	// Normal mode with empty UIDs - should fail (requires UIDs)
	_, err = computeClientCacheKey(authObjNoUID, connObjNoUID, providerUID, false)
	require.Error(t, err, "normal mode should fail with empty UIDs")

	// Standalone mode with UIDs - should succeed (UIDs allowed but not required)
	standaloneKeyWithUIDs, err := computeClientCacheKey(authObjWithUID, connObjWithUID, providerUID, true)
	require.NoError(t, err, "standalone mode should succeed even with UIDs present")

	// Standalone mode with and without UIDs should produce different keys
	assert.NotEqual(t, standaloneKey, standaloneKeyWithUIDs,
		"standalone mode should produce different keys with vs without UIDs due to different spec hashes")
}

func TestComputeClientCacheKeyFromClient(t *testing.T) {
	t.Parallel()
	tests := []computeClientCacheKeyTest{
		{
			name: "valid",
			authObj: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					UID:        authUID,
					Generation: 0,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "ical",
				},
			},
			connObj: &secretsv1beta1.VaultConnection{
				ObjectMeta: metav1.ObjectMeta{
					UID:        connUID,
					Generation: 0,
				},
			},
			providerUID: providerUID,
			want:        ClientCacheKey("ical-" + computedHash),
			wantErr:     assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Client
			if tt.authObj == nil || tt.connObj == nil || tt.providerUID == "" {
				c = &defaultClient{}
			} else {
				c = &defaultClient{
					authObj: tt.authObj,
					connObj: tt.connObj,
					credentialProvider: vault.NewKubernetesCredentialProvider(nil, "",
						tt.providerUID),
				}
			}

			got, err := ComputeClientCacheKeyFromClient(c)
			if !tt.wantErr(t, err, fmt.Sprintf("ComputeClientCacheKeyFromClient(%v)", c)) {
				return
			}
			assert.Equalf(t, tt.want, got, "ComputeClientCacheKeyFromClient(%v)", c)
		})
	}
}

func TestClientCacheKey_IsClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		k    ClientCacheKey
		want bool
	}{
		{
			name: "is-not-a-clone-no-suffix",
			k: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes,
				computedHash)),
			want: false,
		},
		{
			name: "is-not-a-clone-empty-suffix",
			k: ClientCacheKey(fmt.Sprintf("%s-%s-",
				consts.ProviderMethodKubernetes,
				computedHash)),
			want: false,
		},
		{
			name: "is-a-clone",
			k: ClientCacheKey(fmt.Sprintf("%s-%s-ns1/ns2",
				consts.ProviderMethodKubernetes,
				computedHash)),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.k.IsClone(), "IsClone()")
		})
	}
}

func TestClientCacheKeyClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		key       ClientCacheKey
		namespace string
		want      ClientCacheKey
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			key: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes,
				computedHash)),
			namespace: "ns1/ns2",
			want: ClientCacheKey(fmt.Sprintf("%s-%s-ns1/ns2",
				consts.ProviderMethodKubernetes,
				computedHash)),
			wantErr: assert.NoError,
		},
		{
			name: "fail-empty-namespace",
			key: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes,
				computedHash)),
			namespace: "",
			want:      "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "namespace cannot be empty")
			},
		},
		{
			name: "fail-parent-is-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-ns1/ns2",
				consts.ProviderMethodKubernetes,
				computedHash)),
			namespace: "ns3",
			want:      "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "parent key cannot be a clone")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClientCacheKeyClone(tt.key, tt.namespace)
			if !tt.wantErr(t, err, fmt.Sprintf("ClientCacheKeyClone(%v, %v)", tt.key, tt.namespace)) {
				return
			}
			assert.Equalf(t, tt.want, got, "ClientCacheKeyClone(%v, %v)", tt.key, tt.namespace)
		})
	}
}

func TestClientCacheKey_SameParent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     ClientCacheKey
		other   ClientCacheKey
		want    bool
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "same-parent-equal",
			key: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash),
			),
			want:    true,
			wantErr: require.NoError,
		},
		{
			name: "same-parent-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				consts.ProviderMethodKubernetes, computedHash),
			),
			want:    true,
			wantErr: require.NoError,
		},
		{
			name: "other-parent-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				consts.ProviderMethodKubernetes, computedHash2),
			),
			want:    false,
			wantErr: require.NoError,
		},
		{
			name: "invalid-self-hash",
			key: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash[len(computedHash)-1:]),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash),
			),
			want:    false,
			wantErr: require.Error,
		},
		{
			name: "invalid-other-hash",
			key: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s",
				consts.ProviderMethodKubernetes, computedHash[len(computedHash)-1:]),
			),
			want:    false,
			wantErr: require.Error,
		},
		{
			name: "invalid-other-method-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				"invalid", computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				consts.ProviderMethodKubernetes, computedHash),
			),
			want:    false,
			wantErr: require.Error,
		},
		{
			name: "invalid-other-method-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				"invalid", computedHash),
			),
			want:    false,
			wantErr: require.Error,
		},
		{
			name: "invalid-self-hash-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				consts.ProviderMethodKubernetes, computedHash[len(computedHash)-1:]),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				consts.ProviderMethodKubernetes, computedHash),
			),
			want:    false,
			wantErr: require.Error,
		},
		{
			name: "invalid-other-hash-clone",
			key: ClientCacheKey(fmt.Sprintf("%s-%s-/ns1/ns2",
				consts.ProviderMethodKubernetes, computedHash),
			),
			other: ClientCacheKey(fmt.Sprintf("%s-%s-/ns3/ns4",
				consts.ProviderMethodKubernetes, computedHash[len(computedHash)-1:]),
			),
			want:    false,
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.key.SameParent(tt.other)
			tt.wantErr(t, err, fmt.Sprintf("SameParent(%v)", tt.other))
			assert.Equalf(t, tt.want, got,
				"SameParent(%v)", tt.other)
		})
	}
}
