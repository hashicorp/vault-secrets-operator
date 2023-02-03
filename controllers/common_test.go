package controllers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func Test_getConnectionNamespacedName(t *testing.T) {
	tests := []struct {
		name            string
		a               *secretsv1alpha1.VaultAuth
		want            types.NamespacedName
		wantErr         assert.ErrorAssertionFunc
		unsetDefaultsNS bool
	}{
		{
			name: "empty-connection-ref",
			a: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "",
				},
			},
			want: types.NamespacedName{
				Namespace: operatorNamespace,
				Name:      consts.NameDefault,
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
			name: "empty-connection-ref-expect-error",
			a: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
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
			name: "with-connection-ref",
			a: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "qux",
					Namespace: "baz",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					VaultConnectionRef: "foo",
				},
			},
			want: types.NamespacedName{
				Namespace: "baz",
				Name:      "foo",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				valid := err == nil
				if !valid {
					t.Errorf("%s unexpected err: %s", err)
				}
				return valid
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unsetDefaultsNS {
				curDefaultNamespace := operatorNamespace
				operatorNamespace = ""
				t.Cleanup(func() {
					operatorNamespace = curDefaultNamespace
				})
			}
			got, err := getConnectionNamespacedName(tt.a)
			if !tt.wantErr(t, err, fmt.Sprintf("getConnectionNamespacedName(%v)", tt.a)) {
				return
			}
			assert.Equalf(t, tt.want, got, "getConnectionNamespacedName(%v)", tt.a)
		})
	}
}
