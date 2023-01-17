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
	testK8sNamespace := "k8s-tenant-" + strings.ToLower(random.UniqueId())
	testKvMountPath := "kvv2"
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "vaultstaticsecret-kv/terraform",
		Vars: map[string]interface{}{
			"k8s_test_namespace":  testK8sNamespace,
			"k8s_config_context":  "kind-" + clusterName,
			"vault_kv_mount_path": testKvMountPath,
		},
	}
	if entTests := os.Getenv("ENT_TESTS"); entTests != "" {
		testVaultNamespace = "vault-tenant-" + strings.ToLower(random.UniqueId())
		terraformOptions.Vars["vault_enterprise"] = true
		terraformOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	terraformOptions = terraform.WithDefaultRetryableErrors(t, terraformOptions)

	// Clean up resources with "terraform destroy" at the end of the test.
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secret in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
	putSecret := map[string]interface{}{"password": "applejuice"}
	_, err := vClient.KVv2(testKvMountPath).Put(context.Background(), "secret", putSecret)
	require.NoError(t, err)

	// Create a VaultStaticSecret CR to trigger the sync
	testVaultStaticSecret := &secretsv1alpha1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultstaticsecret-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultStaticSecretSpec{
			Namespace:    testVaultNamespace,
			Mount:        testKvMountPath,
			Type:         "kvv2",
			Name:         "secret",
			Dest:         "secret1",
			RefreshAfter: "5s",
		},
	}
	crdClient := getCRDClient(t)

	defer crdClient.Delete(context.Background(), testVaultStaticSecret)
	err = crdClient.Create(context.Background(), testVaultStaticSecret)
	require.NoError(t, err)

	// Wait for the operator to sync Vault secret --> k8s Secret
	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecret.Spec.Dest, testVaultStaticSecret.ObjectMeta.Namespace, putSecret)

	// Change the secret in vault, wait for the VaultStaticSecret refresh, and check
	// the result
	updatedSecret := map[string]interface{}{"password": "orangejuice"}
	_, err = vClient.KVv2(testKvMountPath).Put(context.Background(), "secret", updatedSecret)
	require.NoError(t, err)

	waitForSecretData(t, 10, 1*time.Second, testVaultStaticSecret.Spec.Dest, testVaultStaticSecret.ObjectMeta.Namespace, updatedSecret)
}
