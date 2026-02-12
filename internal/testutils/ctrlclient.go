// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package testutils

import (
	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

// NewFakeClientBuilder returns a fake.ClientBuilder (controller Client) with
// all VSO schemas added. It is useful for testing code that interacts with any
// of the VSO resources.
func NewFakeClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	utilruntime.Must(argorolloutsv1alpha1.AddToScheme(scheme))
	return newFakeClientBuilderWithScheme(scheme)
}

// NewFakeClient returns a fake.Client (controller Client) with all VSO
// schemas added. It is useful for testing code that interacts with any of the
// VSO resources.
func NewFakeClient() client.WithWatch {
	return NewFakeClientBuilder().Build()
}

// NewFakeClientWithScheme returns a fake.Client (controller Client) with the
// provided scheme. It is useful for testing code that interacts with custom
// resources not included in the default VSO scheme.
func NewFakeClientWithScheme(scheme *runtime.Scheme) client.WithWatch {
	return newFakeClientBuilderWithScheme(scheme).Build()
}

func newFakeClientBuilderWithScheme(scheme *runtime.Scheme) *fake.ClientBuilder {
	return fake.NewClientBuilder().WithScheme(scheme)
}
