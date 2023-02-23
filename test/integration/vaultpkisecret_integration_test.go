// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

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

func TestVaultPKISecret(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testPKIMountPath := "pki-" + testID
	testVaultNamespace := ""
	testVaultConnectionName := "vaultconnection-test-tenant-1"
	testVaultAuthMethodName := "vaultauth-test-tenant-1"
	testVaultAuthMethodRole := "role1"

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")
	// Check to see if we are attempting to deploy the controller with Helm.
	deployOperatorWithHelm := os.Getenv("DEPLOY_OPERATOR_WITH_HELM") != ""

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "vaultpkisecret/terraform",
		Vars: map[string]interface{}{
			"deploy_operator_via_helm": deployOperatorWithHelm,
			"k8s_test_namespace":       testK8sNamespace,
			"k8s_config_context":       "kind-" + clusterName,
			"vault_pki_mount_path":     testPKIMountPath,
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
	ctx := context.Background()

	// When we deploy the operator with Helm it will also deploy default VaultConnection/AuthMethod
	// resources, so these are not needed. In this case, we will also clear the VaultAuthRef field of
	// the target secret so that the controller uses the default AuthMethod.
	if !deployOperatorWithHelm {
		// Create a VaultConnection CR
		testVaultConnection := &secretsv1alpha1.VaultConnection{
			ObjectMeta: v1.ObjectMeta{
				Name:      testVaultConnectionName,
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		}

		defer crdClient.Delete(ctx, testVaultConnection)
		err := crdClient.Create(ctx, testVaultConnection)
		require.NoError(t, err)

		// Create a VaultAuth CR
		testVaultAuth := &secretsv1alpha1.VaultAuth{
			ObjectMeta: v1.ObjectMeta{
				Name:      testVaultAuthMethodName,
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultAuthSpec{
				VaultConnectionRef: testVaultConnectionName,
				Namespace:          testVaultNamespace,
				Method:             "kubernetes",
				Mount:              "kubernetes",
				Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
					Role:           testVaultAuthMethodRole,
					ServiceAccount: "default",
					TokenAudiences: []string{"vault"},
				},
			},
		}

		defer crdClient.Delete(ctx, testVaultAuth)
		err = crdClient.Create(ctx, testVaultAuth)
		require.NoError(t, err)
	}

	// Create a VaultPKI CR to trigger the sync
	testVaultPKI := &secretsv1alpha1.VaultPKISecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultpki-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultPKISecretSpec{
			VaultAuthRef: testVaultAuthMethodName,
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
	// The Helm based integration test is expecting to use the default VaultAuthMethod+VaultConnection
	// so in order to get the controller to use the deployed default VaultAuthMethod we need set the VaultAuthRef to "".
	if deployOperatorWithHelm {
		testVaultPKI.Spec.VaultAuthRef = ""
	}

	defer crdClient.Delete(ctx, testVaultPKI)
	err := crdClient.Create(ctx, testVaultPKI)
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
