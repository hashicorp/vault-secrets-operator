// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
)

func TestVaultPKISecret(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testPKIMountPath := "pki-" + testID
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "vaultpkisecret/terraform"),
		tempDir,
		"terraform",
	)
	require.Nil(t, err)
	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
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
	terraformOptions = setCommonTFOptions(t, terraformOptions)

	// Clean up resources with "terraform destroy" at the end of the test.
	t.Cleanup(func() {
		terraform.Destroy(t, terraformOptions)
		os.RemoveAll(tempDir)
	})

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

	ctx := context.Background()
	defer crdClient.Delete(ctx, testVaultConnection)
	err = crdClient.Create(ctx, testVaultConnection)
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
			Method:             "kubernetes",
			Mount:              "kubernetes",
			Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
				Role:           "role1",
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	}

	defer crdClient.Delete(ctx, testVaultAuth)
	err = crdClient.Create(ctx, testVaultAuth)
	require.NoError(t, err)

	// Create a VaultPKI CR to trigger the sync
	testVaultPKI := &secretsv1alpha1.VaultPKISecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultpki-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultPKISecretSpec{
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

	defer crdClient.Delete(ctx, testVaultPKI)
	err = crdClient.Create(ctx, testVaultPKI)
	require.NoError(t, err)

	// Wait for the operator to sync Vault PKI --> k8s Secret, and return the
	// serial number of the generated cert
	serialNumber := waitForPKIData(t, 30, 1*time.Second,
		testVaultPKI.Spec.Dest, testVaultPKI.ObjectMeta.Namespace,
		"test1.example.com", "",
	)
	assert.NotEmpty(t, serialNumber)

	// Use the serial number of the first generated cert to check that the cert
	// is updated
	newSerialNumber := waitForPKIData(t, 30, 2*time.Second,
		testVaultPKI.Spec.Dest, testVaultPKI.ObjectMeta.Namespace,
		"test1.example.com", serialNumber,
	)
	assert.NotEmpty(t, newSerialNumber)
}
