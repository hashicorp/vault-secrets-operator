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
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func TestVaultStaticSecret_kv(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvMountPath := "kv-" + testID
	testKvv2MountPath := "kvv2-" + testID
	testVaultNamespace := ""

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "vaultstaticsecret/terraform"),
		tempDir,
		"terraform",
	)
	require.Nil(t, err)
	// Check to seee if we are attemmpting to deploy the controller with Helm.
	deployOperatorWithHelm := os.Getenv("DEPLOY_OPERATOR_WITH_HELM") != ""

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"deploy_operator_via_helm": deployOperatorWithHelm,
			"k8s_test_namespace":       testK8sNamespace,
			"k8s_config_context":       "kind-" + clusterName,
			"vault_kv_mount_path":      testKvMountPath,
			"vault_kvv2_mount_path":    testKvv2MountPath,
			"operator_helm_chart_path": chartPath,
		},
	}
	if entTests := os.Getenv("ENT_TESTS"); entTests != "" {
		testVaultNamespace = "vault-tenant-" + testID
		terraformOptions.Vars["vault_enterprise"] = true
		terraformOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	terraformOptions = setCommonTFOptions(t, terraformOptions)

	crdClient := getCRDClient(t)
	var created []client.Object
	ctx := context.Background()
	t.Cleanup(func() {
		for _, c := range created {
			// test that the custom resources can be deleted before tf destroy
			// removes the k8s namespace
			assert.Nil(t, crdClient.Delete(ctx, c))
		}
		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, terraformOptions)
		os.RemoveAll(tempDir)
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
	putSecretV1 := map[string]interface{}{"password": "grapejuice", "username": "breakfast", "time": "now"}
	err = vClient.KVv1(testKvMountPath).Put(ctx, "secret", putSecretV1)
	require.NoError(t, err)
	putSecretV2 := map[string]interface{}{"password": "applejuice", "username": "lunch", "time": "later"}
	_, err = vClient.KVv2(testKvv2MountPath).Put(ctx, "secret", putSecretV2)
	require.NoError(t, err)

	// Create a VaultConnection CR
	conns := []*secretsv1alpha1.VaultConnection{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultconnection-test-tenant-1",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}

	// Creates a default VaultConnection CR
	defaultConnection := &secretsv1alpha1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: operatorNS,
		},
		Spec: secretsv1alpha1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}

	auths := []*secretsv1alpha1.VaultAuth{
		// Create a non-default VaultAuth CR
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
	}
	// Create the default VaultAuth CR in the Operator's namespace
	defaultAuthMethod := &secretsv1alpha1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: operatorNS,
		},
		Spec: secretsv1alpha1.VaultAuthSpec{
			VaultConnectionRef: consts.NameDefault,
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

	// The Helm chart will deploy the defaultAuthMethod/Connection
	if !deployOperatorWithHelm {
		conns = append(conns, defaultConnection)
		auths = append(auths, defaultAuthMethod)
	}

	for _, c := range conns {
		require.Nil(t, crdClient.Create(ctx, c))
		created = append(created, c)
	}

	for _, a := range auths {
		require.Nil(t, crdClient.Create(ctx, a))
		created = append(created, a)
	}

	// the order of the test VaultStaticSecret's should match slice of expected secrets.
	secrets := []*secretsv1alpha1.VaultStaticSecret{
		// Create a VaultStaticSecret CR to trigger the sync for kv
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultstaticsecret-test-kv",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultStaticSecretSpec{
				VaultAuthRef: auths[0].ObjectMeta.Name,
				Namespace:    testVaultNamespace,
				Mount:        testKvMountPath,
				Type:         "kv-v1",
				Name:         "secret",
				Dest:         "secretkv",
				RefreshAfter: "5s",
			},
		},
		// Create a VaultStaticSecret CR to trigger the sync for kvv2
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultstaticsecret-test-kvv2",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1alpha1.VaultStaticSecretSpec{
				Namespace:    testVaultNamespace,
				Mount:        testKvv2MountPath,
				Type:         "kv-v2",
				Name:         "secret",
				Dest:         "secretkvv2",
				RefreshAfter: "5s",
			},
		},
	}

	for _, a := range secrets {
		require.Nil(t, crdClient.Create(ctx, a))
		created = append(created, a)
	}

	expected := []map[string]interface{}{putSecretV1, putSecretV2}
	assert.Equal(t, len(expected), len(secrets))
	for i, s := range secrets {
		// Wait for the operator to sync Vault secrets --> k8s Secrets
		waitForSecretData(t, 10, 1*time.Second, s.Spec.Dest, s.ObjectMeta.Namespace, expected[i])
	}

	// Change the secrets in Vault, wait for the VaultStaticSecret's to refresh,
	// and check the result
	updatedSecretV1 := map[string]interface{}{"password": "orangejuice", "time": "morning"}
	err = vClient.KVv1(testKvMountPath).Put(ctx, "secret", updatedSecretV1)
	require.NoError(t, err)
	updatedSecretV2 := map[string]interface{}{"password": "cranberryjuice", "time": "evening"}
	_, err = vClient.KVv2(testKvv2MountPath).Put(ctx, "secret", updatedSecretV2)
	require.NoError(t, err)

	expected = []map[string]interface{}{updatedSecretV1, updatedSecretV2}
	assert.Equal(t, len(expected), len(secrets))
	for i, s := range secrets {
		// Wait for the operator to sync Vault secrets --> k8s Secrets
		waitForSecretData(t, 10, 1*time.Second, s.Spec.Dest, s.ObjectMeta.Namespace, expected[i])
	}
}
