// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestNewAuthLogin(t *testing.T) {
	c := fake.NewClientBuilder().Build()
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
				vaultAuth: &secretsv1alpha1.VaultAuth{
					Spec: secretsv1alpha1.VaultAuthSpec{
						VaultConnectionRef: "foo",
						Namespace:          "baz",
						Method:             "kubernetes",
						Kubernetes:         &secretsv1alpha1.VaultAuthConfigKubernetes{},
					},
				},
				serviceAccountNamespace: "baz",
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
