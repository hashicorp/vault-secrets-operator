package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

// fakeCRClient only satisfies the client.Client interface. No methods are implemented,
// so it shouldn't be used for tests that need them.
type fakeCRClient struct{}

func (fakeCRClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	panic("not implemented")
}

func (fakeCRClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	panic("not implemented")
}

func (fakeCRClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	panic("not implemented")
}

func (fakeCRClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	panic("not implemented")
}

func (fakeCRClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	panic("not implemented")
}

func (fakeCRClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	panic("not implemented")
}

func (fakeCRClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	panic("not implemented")
}

func (fakeCRClient) Status() client.SubResourceWriter {
	panic("not implemented")
}

func (fakeCRClient) SubResource(subResource string) client.SubResourceClient {
	panic("not implemented")
}

func (fakeCRClient) Scheme() *runtime.Scheme {
	panic("not implemented")
}

func (fakeCRClient) RESTMapper() meta.RESTMapper {
	panic("not implemented")
}

func TestNewAuthLogin(t *testing.T) {
	c := fakeCRClient{}
	tests := []struct {
		name         string
		c            client.Client
		va           *secretsv1alpha1.VaultAuth
		k8sNamespace string
		want         AuthLogin
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			va: &secretsv1alpha1.VaultAuth{
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "foo",
					Namespace:          "baz",
					Method:             "kubernetes",
					Kubernetes:         &secretsv1alpha1.VaultAuthConfigKubernetes{},
				},
			},
			c:            c,
			k8sNamespace: "baz",
			want: &KubernetesAuth{
				client: c,
				va: &secretsv1alpha1.VaultAuth{
					Spec: secretsv1alpha1.VaultAuthSpec{
						VaultConnectionRef: "foo",
						Namespace:          "baz",
						Method:             "kubernetes",
						Kubernetes:         &secretsv1alpha1.VaultAuthConfigKubernetes{},
					},
				},
				sans: "baz",
			},
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				valid := err == nil
				if !valid {
					t.Errorf("%s unexpected err: %s", err)
				}
				return valid
			},
		},
		{
			name: "empty-k8s-namespace",
			va: &secretsv1alpha1.VaultAuth{
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "foo",
					Namespace:          "baz",
					Method:             "kubernetes",
				},
			},
			k8sNamespace: "",
			want:         nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorContains(t, err,
					"kubernetes namespace is not set",
					i...,
				)
				return err == nil
			},
		},
		{
			name: "unsupported-method",
			va: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "baz",
					Name:      "foo",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "foo",
					Namespace:          "baz",
					Method:             "unknown",
					Kubernetes:         &secretsv1alpha1.VaultAuthConfigKubernetes{},
				},
			},
			k8sNamespace: "baz",
			want:         nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.EqualError(t, err,
					`unsupported login method "unknown" for AuthLogin "baz/foo"`,
					i...,
				)
				return err == nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAuthLogin(tt.c, tt.va, tt.k8sNamespace)
			if !tt.wantErr(t, err, fmt.Sprintf("NewAuthLogin(%v, %v, %v)", tt.c, tt.va, tt.k8sNamespace)) {
				return
			}
			assert.Equalf(t, tt.want, got, "NewAuthLogin(%v, %v, %v)", tt.c, tt.va, tt.k8sNamespace)
		})
	}
}
