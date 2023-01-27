// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestVaultStaticSecret_kv(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvMountPath := "kv-" + testID
	testKvv2MountPath := "kvv2-" + testID
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "vaultstaticsecret/terraform",
		Vars: map[string]interface{}{
			"k8s_test_namespace":    testK8sNamespace,
			"k8s_config_context":    "kind-" + clusterName,
			"vault_kv_mount_path":   testKvMountPath,
			"vault_kvv2_mount_path": testKvv2MountPath,
		},
	}
	if entTests := os.Getenv("ENT_TESTS"); entTests != "" {
		testVaultNamespace = "vault-tenant-" + testID
		terraformOptions.Vars["vault_enterprise"] = true
		terraformOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	terraformOptions = terraform.WithDefaultRetryableErrors(t, terraformOptions)

	// Clean up resources with "terraform destroy" at the end of the test.
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
	putSecretV1 := map[string]interface{}{"password": "grapejuice", "username": "breakfast", "time": "now"}
	err := vClient.KVv1(testKvMountPath).Put(context.Background(), "secret", putSecretV1)
	require.NoError(t, err)
	putSecretV2 := map[string]interface{}{"password": "applejuice", "username": "lunch", "time": "later"}
	_, err = vClient.KVv2(testKvv2MountPath).Put(context.Background(), "secret", putSecretV2)
	require.NoError(t, err)

	crdClient := getCRDClient(t)

	// Create a VaultConnection CR
	testVaultConnection := &secretsv1alpha1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultconnection-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}

	defer crdClient.Delete(context.Background(), testVaultConnection)
	err = crdClient.Create(context.Background(), testVaultConnection)
	require.NoError(t, err)

	// Create a VaultAuth CR
	testVaultAuth := &secretsv1alpha1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultauth-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultAuthSpec{
			VaultConnectionRef: "vaultconnection-test-tenant-1",
			Namespace:          testVaultNamespace,
		},
	}

	defer crdClient.Delete(context.Background(), testVaultAuth)
	err = crdClient.Create(context.Background(), testVaultAuth)
	require.NoError(t, err)

	// Create a VaultStaticSecret CR to trigger the sync for kv
	testVaultStaticSecret := &secretsv1alpha1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultstaticsecret-test-kv",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultStaticSecretSpec{
			VaultAuthRef: testVaultAuth.ObjectMeta.Name,
			Namespace:    testVaultNamespace,
			Mount:        testKvMountPath,
			Type:         "kv",
			Name:         "secret",
			Dest:         "secretkv",
			RefreshAfter: "5s",
		},
	}

	defer crdClient.Delete(context.Background(), testVaultStaticSecret)
	err = crdClient.Create(context.Background(), testVaultStaticSecret)
	require.NoError(t, err)

	// Create a VaultStaticSecret CR to trigger the sync for kvv2
	testVaultStaticSecretV2 := &secretsv1alpha1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultstaticsecret-test-kvv2",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultStaticSecretSpec{
			VaultAuthRef: testVaultAuth.ObjectMeta.Name,
			Namespace:    testVaultNamespace,
			Mount:        testKvv2MountPath,
			Type:         "kvv2",
			Name:         "secret",
			Dest:         "secretkvv2",
			RefreshAfter: "5s",
		},
	}

	defer crdClient.Delete(context.Background(), testVaultStaticSecretV2)
	err = crdClient.Create(context.Background(), testVaultStaticSecretV2)
	require.NoError(t, err)

	// Wait for the operator to sync Vault secrets --> k8s Secrets
	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecret.Spec.Dest, testVaultStaticSecret.ObjectMeta.Namespace, putSecretV1)
	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecretV2.Spec.Dest, testVaultStaticSecretV2.ObjectMeta.Namespace, putSecretV2)

	// Change the secrets in Vault, wait for the VaultStaticSecret's to refresh,
	// and check the result
	updatedSecretV1 := map[string]interface{}{"password": "orangejuice", "time": "morning"}
	err = vClient.KVv1(testKvMountPath).Put(context.Background(), "secret", updatedSecretV1)
	require.NoError(t, err)
	updatedSecretV2 := map[string]interface{}{"password": "cranberryjuice", "time": "evening"}
	_, err = vClient.KVv2(testKvv2MountPath).Put(context.Background(), "secret", updatedSecretV2)
	require.NoError(t, err)

	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecret.Spec.Dest, testVaultStaticSecret.ObjectMeta.Namespace, updatedSecretV1)
	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecretV2.Spec.Dest, testVaultStaticSecretV2.ObjectMeta.Namespace, updatedSecretV2)
}
