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
					VaultConnectionRef:          "foo",
					VaultConnectionRefNamespace: "bar",
				},
			},
			want: types.NamespacedName{
				Namespace: "bar",
				Name:      "foo",
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
					Name:      "qux",
					Namespace: "baz",
				},
			},
			want: types.NamespacedName{
				Namespace: "baz",
				Name:      "qux",
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
					VaultAuthRef:          tt.a.Name,
					VaultAuthRefNamespace: tt.a.Namespace,
				},
			}
			got, err := GetAuthNamespacedName(obj)
			if !tt.wantErr(t, err, fmt.Sprintf("getAuthNamespacedName(%v)", tt.a)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getAuthNamespacedName(%v)", tt.a)
		})
	}
}
