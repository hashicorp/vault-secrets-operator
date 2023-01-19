package vault

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestNewAuthLogin(t *testing.T) {
	err := secretsv1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	c, err := client.New(
		config.GetConfigOrDie(),
		client.Options{
			Scheme: scheme.Scheme,
		})
	require.NoError(t, err)

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
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
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
			name: "unsupported method",
			va: &secretsv1alpha1.VaultAuth{
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
					`unsupported login method "unknown" for AuthLogin`,
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
