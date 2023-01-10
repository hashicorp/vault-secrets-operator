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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestVaultPKI(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testPKIMountPath := "pki"
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "vaultpki/terraform",
		Vars: map[string]interface{}{
			"k8s_test_namespace":   testK8sNamespace,
			"k8s_config_context":   "kind-" + clusterName,
			"vault_pki_mount_path": testPKIMountPath,
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
	err := crdClient.Create(context.Background(), testVaultConnection)
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

	// Create a VaultPKI CR to trigger the sync
	testVaultPKI := &secretsv1alpha1.VaultPKI{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultpki-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultPKISpec{
			VaultAuthRef: "vaultauth-test-tenant-1",
			Namespace:    testVaultNamespace,
			Mount:        testPKIMountPath,
			Name:         "secret",
			Dest:         "pki1",
			CommonName:   "test1.example.com",
			Format:       "pem",
			Revoke:       true,
			Clear:        true,
			ExpiryOffset: "5s",
			TTL:          "15s",
		},
	}

	defer crdClient.Delete(context.Background(), testVaultPKI)
	err = crdClient.Create(context.Background(), testVaultPKI)
	require.NoError(t, err)

	// Wait for the operator to sync Vault PKI --> k8s Secret
	serialNumber := waitForPKIData(t, 10, 1*time.Second, testVaultPKI.Spec.Dest, testVaultPKI.ObjectMeta.Namespace, "test1.example.com", "")
	assert.NotEmpty(t, serialNumber)

	newSerialNumber := waitForPKIData(t, 30, 2*time.Second, testVaultPKI.Spec.Dest, testVaultPKI.ObjectMeta.Namespace, "test1.example.com", serialNumber)
	assert.NotEmpty(t, newSerialNumber)
}
