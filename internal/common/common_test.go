// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package common

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func Test_GetConnectionNamespacedName(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

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
	t.Parallel()

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

func TestNewSyncableSecretMetaData(t *testing.T) {
	t.Parallel()

	namespace := "qux"
	name := "foo"
	newTypeMeta := func(kind string) metav1.TypeMeta {
		return metav1.TypeMeta{
			Kind:       kind,
			APIVersion: secretsv1beta1.GroupVersion.Version,
		}
	}
	objectMeta := metav1.ObjectMeta{
		Namespace: namespace,
		Name:      name,
	}
	destination := secretsv1beta1.Destination{
		Name:   "baz",
		Create: true,
	}
	authRef := "default"
	newSecretMetaData := func(kind string) *SyncableSecretMetaData {
		return &SyncableSecretMetaData{
			Kind:        kind,
			APIVersion:  secretsv1beta1.GroupVersion.Version,
			Namespace:   namespace,
			Name:        name,
			Destination: &destination,
			AuthRef:     authRef,
		}
	}

	tests := []struct {
		name    string
		obj     client.Object
		want    *SyncableSecretMetaData
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "hcpvsa",
			obj: &secretsv1beta1.HCPVaultSecretsApp{
				TypeMeta:   newTypeMeta("HCPVaultSecretsApp"),
				ObjectMeta: objectMeta,
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					HCPAuthRef:  authRef,
					Destination: destination,
				},
			},
			want:    newSecretMetaData("HCPVaultSecretsApp"),
			wantErr: assert.NoError,
		},
		{
			name: "vds",
			obj: &secretsv1beta1.VaultDynamicSecret{
				TypeMeta:   newTypeMeta("VaultDynamicSecret"),
				ObjectMeta: objectMeta,
				Spec: secretsv1beta1.VaultDynamicSecretSpec{
					VaultAuthRef: authRef,
					Destination:  destination,
				},
			},
			want:    newSecretMetaData("VaultDynamicSecret"),
			wantErr: assert.NoError,
		},
		{
			name: "vps",
			obj: &secretsv1beta1.VaultPKISecret{
				TypeMeta:   newTypeMeta("VaultPKISecret"),
				ObjectMeta: objectMeta,
				Spec: secretsv1beta1.VaultPKISecretSpec{
					VaultAuthRef: authRef,
					Destination:  destination,
				},
			},
			want:    newSecretMetaData("VaultPKISecret"),
			wantErr: assert.NoError,
		},
		{
			name: "vss",
			obj: &secretsv1beta1.VaultStaticSecret{
				TypeMeta:   newTypeMeta("VaultStaticSecret"),
				ObjectMeta: objectMeta,
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultAuthRef: authRef,
					Destination:  destination,
				},
			},
			want:    newSecretMetaData("VaultStaticSecret"),
			wantErr: assert.NoError,
		},
		{
			name: "unsupported-type",
			obj:  &corev1.Secret{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, fmt.Sprintf("unsupported type %T", &corev1.Secret{}))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSyncableSecretMetaData(tt.obj)
			if !tt.wantErr(t, err, fmt.Sprintf("NewSyncableSecretMetaData(%v)", tt.obj)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewSyncableSecretMetaData(%v)", tt.obj)
		})
	}
}

func newClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}

func Test_MergeInVaultAuthGlobal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	builder := newClientBuilder()

	gObj := &secretsv1beta1.VaultAuthGlobal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "buz",
			Namespace: "baz",
		},
		Spec: secretsv1beta1.VaultAuthGlobalSpec{
			VaultConnectionRef: "default",
			DefaultHeaders: map[string]string{
				"X-Global-Default": "bar",
			},
			Kubernetes: &secretsv1beta1.VaultAuthGlobalConfigKubernetes{
				Namespace: "biff",
				Mount:     "qux",
				Headers: map[string]string{
					"X-Global-Kubernetes": "qux",
				},
				VaultAuthConfigKubernetes: secretsv1beta1.VaultAuthConfigKubernetes{
					Role:                   "beetle",
					ServiceAccount:         "sa1",
					TokenExpirationSeconds: 200,
					TokenAudiences:         []string{"baz"},
				},
			},
			AppRole: &secretsv1beta1.VaultAuthGlobalConfigAppRole{
				Namespace: "biff",
				Mount:     "qux",
				VaultAuthConfigAppRole: secretsv1beta1.VaultAuthConfigAppRole{
					RoleID:    "foo",
					SecretRef: "bar",
				},
			},
			JWT: &secretsv1beta1.VaultAuthGlobalConfigJWT{
				Namespace: "biff",
				Mount:     "qux",
				VaultAuthConfigJWT: secretsv1beta1.VaultAuthConfigJWT{
					Role:           "beetle",
					ServiceAccount: "sa1",
				},
			},
			AWS: &secretsv1beta1.VaultAuthGlobalConfigAWS{
				Namespace: "biff",
				Mount:     "qux",
				VaultAuthConfigAWS: secretsv1beta1.VaultAuthConfigAWS{
					Role:   "beetle",
					Region: "us-east-1",
				},
			},
			GCP: &secretsv1beta1.VaultAuthGlobalConfigGCP{
				Namespace: "biff",
				Mount:     "qux",
				VaultAuthConfigGCP: secretsv1beta1.VaultAuthConfigGCP{
					Role:                           "beetle",
					Region:                         "us-west1",
					WorkloadIdentityServiceAccount: "sa1",
				},
			},
		},
	}

	tests := []struct {
		name    string
		c       client.Client
		o       *secretsv1beta1.VaultAuth
		gObj    *secretsv1beta1.VaultAuthGlobal
		want    *secretsv1beta1.VaultAuth
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "set-kubernetes",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Headers: map[string]string{
						"X-Local": "buz",
					},
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "kubernetes",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "kubernetes",
					Namespace: "biff",
					Mount:     "qux",
					Headers: map[string]string{
						"X-Local":             "buz",
						"X-Global-Default":    "bar",
						"X-Global-Kubernetes": "qux",
					},
					Params: map[string]string{},
					Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
						Role:                   "beetle",
						ServiceAccount:         "sa1",
						TokenExpirationSeconds: 200,
						TokenAudiences:         []string{"baz"},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "override-kubernetes",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "other",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "kubernetes",
					Mount:     "qux",
					Namespace: "biff",
					Params:    map[string]string{},
					Headers: map[string]string{
						"X-Global-Default":    "bar",
						"X-Global-Kubernetes": "qux",
					},
					Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
						ServiceAccount: "sa1",
						TokenAudiences: []string{"qux"},
					},
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "other",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "kubernetes",
					Namespace: "biff",
					Mount:     "qux",
					Params:    map[string]string{},
					Headers: map[string]string{
						"X-Global-Default":    "bar",
						"X-Global-Kubernetes": "qux",
					},
					Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
						Role:                   "beetle",
						ServiceAccount:         "sa1",
						TokenExpirationSeconds: 200,
						TokenAudiences:         []string{"qux"},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "set-jwt",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "jwt",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "jwt",
					Namespace: "biff",
					Mount:     "qux",
					Params:    map[string]string{},
					Headers: map[string]string{
						"X-Global-Default": "bar",
					},
					JWT: &secretsv1beta1.VaultAuthConfigJWT{
						Role:           "beetle",
						ServiceAccount: "sa1",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "set-appRole",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "appRole",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "appRole",
					Namespace: "biff",
					Mount:     "qux",
					Headers: map[string]string{
						"X-Global-Default": "bar",
					},
					Params: map[string]string{},
					AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
						RoleID:    "foo",
						SecretRef: "bar",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "set-aws",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "none",
							Params:  "none",
						},
					},
					Method: "aws",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "none",
							Params:  "none",
						},
					},
					Method:    "aws",
					Namespace: "biff",
					Mount:     "qux",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:   "beetle",
						Region: "us-east-1",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "set-gcp",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "gcp",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "gcp",
					Namespace: "biff",
					Mount:     "qux",
					Headers: map[string]string{
						"X-Global-Default": "bar",
					},
					Params: map[string]string{},
					GCP: &secretsv1beta1.VaultAuthConfigGCP{
						Role:                           "beetle",
						Region:                         "us-west1",
						WorkloadIdentityServiceAccount: "sa1",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "global-ref-not-set",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{},
			},
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{},
			},
			wantErr: assert.NoError,
		},
		{
			name: "union-headers",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Headers: map[string]string{
						"X-Local": "buz",
					},
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "kubernetes",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "kubernetes",
					Namespace: "biff",
					Mount:     "qux",
					Headers: map[string]string{
						"X-Local":             "buz",
						"X-Global-Default":    "bar",
						"X-Global-Kubernetes": "qux",
					},
					Params: map[string]string{},
					Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
						Role:                   "beetle",
						ServiceAccount:         "sa1",
						TokenExpirationSeconds: 200,
						TokenAudiences:         []string{"baz"},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "union-headers-override",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Headers: map[string]string{
						"X-Local":          "buz",
						"X-Global-Default": "override",
					},
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method: "kubernetes",
				},
			},
			gObj: gObj.DeepCopy(),
			want: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					Namespace:       "baz",
					ResourceVersion: "1",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultConnectionRef: "default",
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
						MergeStrategy: secretsv1beta1.MergeStrategy{
							Headers: "union",
							Params:  "union",
						},
					},
					Method:    "kubernetes",
					Namespace: "biff",
					Mount:     "qux",
					Headers: map[string]string{
						"X-Local":             "buz",
						"X-Global-Default":    "override",
						"X-Global-Kubernetes": "qux",
					},
					Params: map[string]string{},
					Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
						Role:                   "beetle",
						ServiceAccount:         "sa1",
						TokenExpirationSeconds: 200,
						TokenAudiences:         []string{"baz"},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-method",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
					},
					Method: "invalid",
				},
			},
			gObj: gObj.DeepCopy(),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`unsupported auth method "invalid" for global auth merge`)
			},
		},
		{
			name: "invalid-global-ref",
			c:    builder.Build(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "baz",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "invalid",
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.ErrorContains(t, err, "failed getting baz/invalid, err=") {
					return assert.True(t, errors.IsNotFound(err), i...)
				}
				return false
			},
		},
		{
			name: "invalid-nil-auth-config",
			c:    builder.Build(),
			gObj: &secretsv1beta1.VaultAuthGlobal{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "baz",
					Name:      "buz",
				},
			},
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "baz",
					Name:      "foo",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name: "buz",
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "no auth method set in VaultAuth baz/foo")
			},
		},
		{
			name: "invalid-not-allowed-namespace",
			c:    builder.Build(),
			gObj: gObj.DeepCopy(),
			o: &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "other",
					Name:      "foo",
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					VaultAuthGlobalRef: &secretsv1beta1.VaultAuthGlobalRef{
						Name:      "buz",
						Namespace: "baz",
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if assert.ErrorContains(t, err,
					`target namespace "other" is not allowed by kind=VaultAuthGlobal obj=baz/buz`,
				) {
					var wantErr *NamespaceNotAllowedError
					return assert.ErrorAs(t, err, &wantErr)
				}
				return false
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.o != nil {
				require.NoError(t, tt.c.Create(ctx, tt.o))
			}
			if tt.gObj != nil {
				require.NoError(t, tt.c.Create(ctx, tt.gObj))
			}

			got, _, err := MergeInVaultAuthGlobal(ctx, tt.c, tt.o)
			if !tt.wantErr(t, err, fmt.Sprintf("MergeInVaultAuthGlobal(%v, %v, %v)", ctx, tt.c, tt.o)) {
				return
			}
			assert.Equalf(t, tt.want, got, "MergeInVaultAuthGlobal(%v, %v, %v)", ctx, tt.c, tt.o)
		})
	}
}
