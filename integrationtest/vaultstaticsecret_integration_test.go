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
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func TestVaultStaticSecret_kv(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvMountPath := "kvv2-" + testID
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "vaultstaticsecret-kv/terraform",
		Vars: map[string]interface{}{
			// TODO: get this dynamically
			// KUBERNETES_SERVICE_HOST=10.96.0.1
			"k8s_host":            "https://10.96.0.1",
			"k8s_test_namespace":  testK8sNamespace,
			"k8s_config_context":  "kind-" + clusterName,
			"vault_kv_mount_path": testKvMountPath,
		},
	}
	if entTests := os.Getenv("ENT_TESTS"); entTests != "" {
		testVaultNamespace = "vault-tenant-" + testID
		terraformOptions.Vars["vault_enterprise"] = true
		terraformOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	terraformOptions = terraform.WithDefaultRetryableErrors(t, terraformOptions)

	crdClient := getCRDClient(t)
	var created []client.Object
	t.Cleanup(func() {
		ctx := context.Background()
		for _, c := range created {
			// test that the custom resources can be deleted before tf destroy
			// removes the k8s namespace
			assert.Nil(t, crdClient.Delete(ctx, c))
		}
		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, terraformOptions)
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secret in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
	putSecret := map[string]interface{}{"password": "applejuice"}
	_, err := vClient.KVv2(testKvMountPath).Put(context.Background(), "secret", putSecret)
	require.NoError(t, err)

	// Create a VaultConnection CR
	connections := []*secretsv1alpha1.VaultConnection{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultconnection-test-tenant-1",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.DefaultNameVaultConnection,
				Namespace: operatorNS,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}

	// Create a VaultAuth CR
	auths := []*secretsv1alpha1.VaultAuth{
		{
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
		},
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.DefaultNameVaultConnection,
				Namespace: operatorNS,
			},
			Spec: secretsv1alpha1.VaultAuthSpec{
				VaultConnectionRef: consts.DefaultNameVaultConnection,
				Namespace:          testVaultNamespace,
				Method:             "kubernetes",
				Mount:              "kubernetes",
				Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
					Role:           "role1",
					ServiceAccount: "default",
					TokenAudiences: []string{"vault"},
				},
			},
		},
	}

	for _, c := range connections {
		ctx := context.Background()
		require.Nil(t, crdClient.Create(ctx, c))
		created = append(created, c)
	}

	for _, a := range auths {
		ctx := context.Background()
		require.Nil(t, crdClient.Create(ctx, a))
		created = append(created, a)
	}

	// Create a VaultStaticSecret CR to trigger the sync
	testVaultStaticSecret := &secretsv1alpha1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultstaticsecret-test-tenant-1",
			Namespace: testK8sNamespace,
		},
		Spec: secretsv1alpha1.VaultStaticSecretSpec{
			// VaultAuthRef: "vaultauth-test-tenant-1",
			Namespace:    testVaultNamespace,
			Mount:        testKvMountPath,
			Type:         "kvv2",
			Name:         "secret",
			Dest:         "secret1",
			RefreshAfter: "5s",
		},
	}

	created = append(created, testVaultStaticSecret)
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
