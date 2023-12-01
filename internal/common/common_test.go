// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

func Test_getAuthRefNamespacedName(t *testing.T) {
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
			got, err := getAuthRefNamespacedName(obj)
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
			allowed := isAllowedNamespace(tt.a, tt.targetNamespace, tt.a.Spec.AllowedNamespaces...)
			assert.Equal(t, allowed, tt.expected)
		})
	}
}

func TestGetHCPAuthForObj(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme)

	ctx := context.Background()
	tests := []struct {
		name     string
		client   client.Client
		obj      client.Object
		want     *secretsv1beta1.HCPAuth
		hcpAuths []*secretsv1beta1.HCPAuth
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:   "relative-namespace",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "foo",
						Name:      "baz",
					},
				},
			},
			want: &secretsv1beta1.HCPAuth{
				TypeMeta: metav1.TypeMeta{
					Kind:       "HCPAuth",
					APIVersion: "secrets.hashicorp.com/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "foo",
					Name:            "baz",
					ResourceVersion: "1",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "external-namespace-allowed",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "ns1/baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "baz",
					},
					Spec: secretsv1beta1.HCPAuthSpec{
						AllowedNamespaces: []string{"foo"},
					},
				},
			},
			want: &secretsv1beta1.HCPAuth{
				TypeMeta: metav1.TypeMeta{
					Kind:       "HCPAuth",
					APIVersion: "secrets.hashicorp.com/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "ns1",
					Name:            "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.HCPAuthSpec{
					AllowedNamespaces: []string{"foo"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "external-namespace-allowed-wildcard",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "ns1/baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "baz",
					},
					Spec: secretsv1beta1.HCPAuthSpec{
						AllowedNamespaces: []string{"*"},
					},
				},
			},
			want: &secretsv1beta1.HCPAuth{
				TypeMeta: metav1.TypeMeta{
					Kind:       "HCPAuth",
					APIVersion: "secrets.hashicorp.com/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "ns1",
					Name:            "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.HCPAuthSpec{
					AllowedNamespaces: []string{"*"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "external-namespace-disallowed-unset",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "ns1/baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "baz",
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				var wantErr *NamespaceNotAllowedError
				return assert.ErrorAs(t, err, &wantErr)
			},
		},
		{
			name:   "external-namespace-disallowed-other",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "ns1/baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "baz",
					},
					Spec: secretsv1beta1.HCPAuthSpec{
						AllowedNamespaces: []string{"qux"},
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				var wantErr *NamespaceNotAllowedError
				return assert.ErrorAs(t, err, &wantErr)
			},
		},
		{
			name:   "external-namespace-disallowed-invalid",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "ns1/baz",
				},
			},
			hcpAuths: []*secretsv1beta1.HCPAuth{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "baz",
					},
					Spec: secretsv1beta1.HCPAuthSpec{
						AllowedNamespaces: []string{"*", "qux"},
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				var wantErr *NamespaceNotAllowedError
				return assert.ErrorAs(t, err, &wantErr)
			},
		},
		{
			name:   "relative-not-found",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "baz",
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return errors.IsNotFound(err)
			},
		},
		{
			name:   "external-not-found",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: "foo",
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef: "qux/baz",
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return errors.IsNotFound(err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, obj := range tt.hcpAuths {
				assert.NoError(t, tt.client.Create(ctx, obj))
			}

			m := defaultMaxRetries
			t.Cleanup(func() {
				defaultMaxRetries = m
			})

			// monkey patch defaultMaxRetries to expedite test execution
			defaultMaxRetries = uint64(1)

			got, err := GetHCPAuthForObj(ctx, tt.client, tt.obj)
			if !tt.wantErr(t, err, fmt.Sprintf("GetHCPAuthForObj(%v, %v, %v)", ctx, tt.client, tt.obj)) {
				return
			}
			assert.Equalf(t, tt.want, got, "GetHCPAuthForObj(%v, %v, %v)", ctx, tt.client, tt.obj)
		})
	}
}
