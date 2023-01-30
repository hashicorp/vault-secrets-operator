package vault

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	v12 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestKubernetesAuth_SetK8SNamespace(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "basic",
			want: "baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &KubernetesAuth{}
			l.SetK8SNamespace(tt.want)
			assert.Equalf(t, tt.want, l.sans, "SetK8SNamespace(%q)", tt.want)
		})
	}
}

func TestKubernetesAuth_GetK8SNamespace(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "basic",
			want: "baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &KubernetesAuth{}
			l.SetK8SNamespace(tt.want)
			assert.Equalf(t, tt.want, l.GetK8SNamespace(), "GetK8SNamespace(%q)", tt.want)
		})
	}
}

func TestKubernetesAuth_getSATokenRequest(t *testing.T) {
	tests := []struct {
		name    string
		va      *v1alpha1.VaultAuth
		sans    string
		want    *v12.TokenRequest
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "basic",
			va: &secretsv1alpha1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "baz",
					Name:      "foo",
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					Namespace: "baz",
					Method:    "kubernetes",
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						TokenAudiences:         []string{"buz", "qux"},
						TokenExpirationSeconds: 1200,
						TokenGenerateName:      "baz",
					},
				},
			},
			want: &v12.TokenRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "baz",
				},
				Spec: v12.TokenRequestSpec{
					ExpirationSeconds: pointer.Int64(1200),
					Audiences:         []string{"buz", "qux"},
				},
				Status: v12.TokenRequestStatus{},
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
			l := &KubernetesAuth{
				va:   tt.va,
				sans: tt.sans,
			}
			got, err := l.getSATokenRequest()
			if !tt.wantErr(t, err, fmt.Sprintf("getSATokenRequest()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "getSATokenRequest()")
		})
	}
}
