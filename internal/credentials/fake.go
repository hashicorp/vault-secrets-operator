// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credentials

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/provider"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/vault"
)

type FakeCredentialProviderFactory interface {
	CredentialProviderFactory
}

type FakeCredentialProvider interface {
	vault.CredentialProvider
	WithUID(types.UID) FakeCredentialProvider
}

func NewFakeCredentialProvider() FakeCredentialProvider {
	return &fakeCredentialProvider{}
}

var _ FakeCredentialProvider = (*fakeCredentialProvider)(nil)

type fakeCredentialProvider struct {
	uid types.UID
}

func (f *fakeCredentialProvider) WithUID(uid types.UID) FakeCredentialProvider {
	f.uid = uid
	return f
}

func (f *fakeCredentialProvider) GetUID() types.UID {
	return f.uid
}

func (f *fakeCredentialProvider) GetNamespace() string {
	return ""
}

func (f *fakeCredentialProvider) GetCreds(_ context.Context, _ ctrlclient.Client) (map[string]interface{}, error) {
	return nil, nil
}

func (f *fakeCredentialProvider) Init(_ context.Context, _ ctrlclient.Client, _ *secretsv1beta1.VaultAuth, _ string) error {
	return nil
}

var _ FakeCredentialProviderFactory = (*fakeCredentialProviderFactory)(nil)

type fakeCredentialProviderFactory struct {
	factoryFunc CredentialProviderFactoryFunc
}

func (f *fakeCredentialProviderFactory) New(ctx context.Context, c ctrlclient.Client, obj ctrlclient.Object, providerNamespace string) (provider.CredentialProviderBase, error) {
	return f.factoryFunc(ctx, c, obj, providerNamespace)
}

// NewFakeCredentialProviderFactory returns a new FakeCredentialProviderFactory
// with the given factoryFunc. If factoryFunc is nil, a default factoryFunc is
// used. The default factoryFunc returns a fakeCredentialProvider for
// VaultAuth objects with the Kubernetes authentication method.
func NewFakeCredentialProviderFactory(factoryFunc CredentialProviderFactoryFunc) CredentialProviderFactory {
	return &fakeCredentialProviderFactory{
		factoryFunc: factoryFunc,
	}
}
