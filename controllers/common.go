package controllers

import (
	"context"
	"fmt"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
	"github.com/hashicorp/vault/api"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func getVaultConfig(ctx context.Context, client client.Client, nameAndNamespace types.NamespacedName) (*vault.VaultClientConfig, error) {
	vaultAuth, err := getVaultAuth(ctx, client, nameAndNamespace)
	if err != nil {
		return nil, err
	}
	vaultConnection, err := getVaultConnection(ctx, client, types.NamespacedName{Namespace: nameAndNamespace.Namespace, Name: vaultAuth.Spec.VaultConnectionRef})
	if err != nil {
		return nil, err
	}
	// TODO: support a default auth and connection
	vaultConfig := &vault.VaultClientConfig{
		CACertSecretRef: vaultConnection.Spec.CACertSecretRef,
		K8sNamespace:    nameAndNamespace.Namespace,
		Address:         vaultConnection.Spec.Address,
		SkipTLSVerify:   vaultConnection.Spec.SkipTLSVerify,
		TLSServerName:   vaultConnection.Spec.TLSServerName,
		VaultNamespace:  vaultAuth.Spec.Namespace,
		// TODO: get this from the service account, setup k8s-auth, etc.
		Token: "root",
	}
	return vaultConfig, nil
}

func getVaultConnection(ctx context.Context, client client.Client, nameAndNamespace types.NamespacedName) (*secretsv1alpha1.VaultConnection, error) {
	l := log.FromContext(ctx)
	connObj := &secretsv1alpha1.VaultConnection{}
	if err := client.Get(ctx, nameAndNamespace, connObj); err != nil {
		l.Error(err, "error getting resource from k8s", "VaultConnection", connObj)
		return nil, err
	}
	return connObj, nil
}

func getVaultAuth(ctx context.Context, client client.Client, nameAndNamespace types.NamespacedName) (*secretsv1alpha1.VaultAuth, error) {
	l := log.FromContext(ctx)
	authObj := &secretsv1alpha1.VaultAuth{}
	if err := client.Get(ctx, nameAndNamespace, authObj); err != nil {
		l.Error(err, "error getting resource from k8s", "VaultAuth", authObj)
		return nil, err
	}
	return authObj, nil
}

func getVaultClient(ctx context.Context, vaultConfig *vault.VaultClientConfig, client client.Client) (*api.Client, error) {
	l := log.FromContext(ctx)

	c, err := vault.MakeVaultClient(ctx, vaultConfig, client)
	if err != nil {
		l.Error(err, "error setting up Vault API client")
		return nil, err
	}

	c.SetToken(vaultConfig.Token)

	l.Info(fmt.Sprintf("Getting Vault client, ns=%q", vaultConfig.VaultNamespace))
	if vaultConfig.VaultNamespace != "" {
		c.SetNamespace(vaultConfig.VaultNamespace)
	}
	return c, nil
}
