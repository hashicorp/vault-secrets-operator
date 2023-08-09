// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func Test_GetConnectionNamespacedName(t *testing.T) {
	tests := []struct {
		name            string
		a               *secretsv1beta1.VaultAuth
		want            types.NamespacedName
		wantErr         assert.ErrorAssertionFunc
		unsetDefaultsNS bool
	}{
		{
			name: "empty-connection-ref",
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "",
				},
			},
			want: types.NamespacedName{
				Namespace: OperatorNamespace,
				Name:      consts.NameDefault,
			},
			wantErr: assert.NoError,
		},
		{
			name: "empty-connection-ref-expect-error",
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "",
				},
			},
			want: types.NamespacedName{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "operator's default namespace is not set, this is a bug", i...)
				return err != nil
			},
			unsetDefaultsNS: true,
		},
		{
			name: "with-connection-ref-with-ns",
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "foo/bar",
				},
			},
			want: types.NamespacedName{
				Name:      "bar",
				Namespace: "foo",
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-connection-ref-without-ns",
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "foo",
				},
			},
			want: types.NamespacedName{
				Namespace: "baz",
				Name:      "foo",
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unsetDefaultsNS {
				curDefaultNamespace := OperatorNamespace
				OperatorNamespace = ""
				t.Cleanup(func() {
					OperatorNamespace = curDefaultNamespace
				})
			}
			got, err := GetConnectionNamespacedName(tt.a)
			if !tt.wantErr(t, err, fmt.Sprintf("getConnectionNamespacedName(%v)", tt.a)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getConnectionNamespacedName(%v)", tt.a)
		})
	}
}

func Test_GetAuthNamespacedName(t *testing.T) {
	SecretNamespace := "foo"
	tests := []struct {
		name    string
		a       *secretsv1beta1.VaultAuth
		want    types.NamespacedName
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "empty-auth-ref", // ns comes from the OperatorNS
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			want: types.NamespacedName{
				Namespace: OperatorNamespace,
				Name:      consts.NameDefault,
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-auth-ref-with-ns", // ns comes from the Auth
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "baz/qux",
				},
			},
			want: types.NamespacedName{
				Name:      "qux",
				Namespace: "baz",
			},
			wantErr: assert.NoError,
		},
		{
			name: "with-auth-ref-without-ns", // ns comes from the Secret
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "qux",
				},
			},
			want: types.NamespacedName{
				Namespace: SecretNamespace,
				Name:      "qux",
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid auth name", // ns comes from the Secret
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo/bar/baz/qux",
				},
			},
			want: types.NamespacedName{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err, "invalid name: foo/bar/baz/qux", i...)
				return err != nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only testing VSS because it's the same logic for all secret types.
			obj := &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: SecretNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultAuthRef: tt.a.Name,
				},
			}
			// TargetName is always just the object name+ns
			got, err := GetAuthAndTargetNamespacedName(obj)
			if !tt.wantErr(t, err, fmt.Sprintf("getAuthNamespacedName(%v)", tt.a)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getAuthNamespacedName(%v)", tt.a)
		})
	}
}

func Test_isAllowedNamespace(t *testing.T) {
	tests := []struct {
		name            string
		a               *secretsv1beta1.VaultAuth
		targetNamespace string
		expected        bool
	}{
		{
			name: "wildcard-filter", // allow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo/bar",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: []string{"*"},
				},
			},
			targetNamespace: "baz",
			expected:        true,
		},
		{
			name: "list of filters with target ns included", // allow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo/bar",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: []string{"foo", "bar", "baz"},
				},
			},
			targetNamespace: "baz",
			expected:        true,
		},
		{
			name: "target and auth method in same ns", // allow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bar",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.VaultAuthSpec{},
			},
			targetNamespace: "foo",
			expected:        true,
		},
		{
			name: "default auth method is used", // allow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: OperatorNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: []string{"foo", "bar", "baz"},
				},
			},
			targetNamespace: "baz",
			expected:        true,
		},
		{
			name: "list of filters with target ns excluded", // disallow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo/bar",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: []string{"foo", "bar"},
				},
			},
			targetNamespace: "baz",
			expected:        false,
		},
		{
			name: "nil-filter-slice", // disallow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: nil,
				},
			},
			targetNamespace: "foo",
			expected:        false,
		},
		{
			name: "empty-filter-slice", // disallow
			a: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bar",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					AllowedNamespaces: []string{},
				},
			},
			targetNamespace: "foo",
			expected:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TargetName is always just the object name+ns
			allowed := isAllowedNamespace(tt.a, tt.targetNamespace)
			assert.Equal(t, allowed, tt.expected)
		})
	}
}
