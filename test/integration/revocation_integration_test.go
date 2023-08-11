// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvv2MountPath := consts.KVSecretTypeV2 + testID
	testVaultNamespace := ""
	testNamePrefix := "revocation"
	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")
	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	// TF related setup
	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)
	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "revocation/terraform"),
		tempDir,
		"terraform",
	)
	require.Nil(t, err)

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_vault_connection_address": testVaultAddress,
			"k8s_test_namespace":           testK8sNamespace,
			"k8s_config_context":           k8sConfigContext,
			"vault_kvv2_mount_path":        testKvv2MountPath,
			"operator_helm_chart_path":     chartPath,
			"name_prefix":                  testNamePrefix,
		},
	}
	if operatorImageRepo != "" {
		tfOptions.Vars["operator_image_repo"] = operatorImageRepo
	}
	if operatorImageTag != "" {
		tfOptions.Vars["operator_image_tag"] = operatorImageTag
	}
	if entTests {
		testVaultNamespace = "vault-tenant-" + testID
		tfOptions.Vars["vault_enterprise"] = true
		tfOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

	crdClient := getCRDClient(t)
	var created []ctrlclient.Object

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, tfOptions)

	// Parse terraform output
	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.Nil(t, err)

	var outputs revocationK8sOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)

	auths := []*secretsv1beta1.VaultAuth{
		// Create a non-default VaultAuth CR
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultauth-test-kubernetes",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1beta1.VaultAuthSpec{
				Namespace: testVaultNamespace,
				Method:    "kubernetes",
				Mount:     "kubernetes",
				Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
					Role:           outputs.AuthRole,
					ServiceAccount: consts.NameDefault,
					TokenAudiences: []string{"vault"},
				},
			},
		},
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultauth-test-jwt-serviceaccount",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1beta1.VaultAuthSpec{
				Namespace: testVaultNamespace,
				Method:    "jwt",
				Mount:     "jwt",
				JWT: &secretsv1beta1.VaultAuthConfigJWT{
					Role:           outputs.AuthRole,
					ServiceAccount: consts.NameDefault,
					TokenAudiences: []string{"vault"},
				},
			},
		},
	}

	// apply all the Auth Methods
	for _, auth := range auths {
		require.Nil(t, crdClient.Create(ctx, auth))
		created = append(created, auth)
	}

	t.Cleanup(func() {
		// As VSO deployment was deleted earlier, we don't have the reconciliation loops to remove the finalizers of
		// the CRs created in k8s test namespace. They need to be manually removed before deleting the CRs.
		for _, auth := range auths {
			assert.NoError(t,
				crdClient.Patch(ctx, auth, ctrlclient.RawPatch(types.JSONPatchType, []byte(`[ { "op": "remove", "path": "/metadata/finalizers" } ]`))),
				fmt.Sprintf("Unable to update finalizer for %s", auth.Name))
		}

		for _, c := range created {
			// test that the custom resources can be deleted before tf destroy
			// removes the k8s namespace
			assert.Nil(t, crdClient.Delete(ctx, c))
		}
		exportKindLogs(t)

		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, tfOptions)
		os.RemoveAll(tempDir)
	})

	secrets := []*secretsv1beta1.VaultStaticSecret{}
	// create the VSS secrets
	for _, a := range auths {
		dest := fmt.Sprintf("kv-%s", a.Name)
		secretName := fmt.Sprintf("test-secret-%s", a.Name)
		secrets = append(secrets,
			&secretsv1beta1.VaultStaticSecret{
				ObjectMeta: v1.ObjectMeta{
					Name:      secretName,
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultAuthRef: a.Name,
					Namespace:    testVaultNamespace,
					Mount:        testKvv2MountPath,
					Type:         consts.KVSecretTypeV2,
					Path:         dest,
					Destination: secretsv1beta1.Destination{
						Name:   dest,
						Create: true,
					},
				},
			})
	}
	// Add to the created for cleanup
	for _, secret := range secrets {
		created = append(created, secret)
	}

	expectedData := map[string]interface{}{"foo": "bar"}
	putKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret) {
		_, err := vClient.KVv2(testKvv2MountPath).Put(ctx, vssObj.Spec.Path, expectedData)
		require.NoError(t, err)
	}

	deleteKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret) {
		require.NoError(t, vClient.KVv2(testKvv2MountPath).Delete(ctx, vssObj.Spec.Path))
	}

	assertSync := func(t *testing.T, obj *secretsv1beta1.VaultStaticSecret) {
		secret, err := waitForSecretData(t, ctx, crdClient, 30, 1*time.Second, obj.Spec.Destination.Name,
			obj.ObjectMeta.Namespace, expectedData)
		if !assert.NoError(t, err) {
			return
		}
		assertSyncableSecret(t, crdClient, obj, secret)
	}

	for idx := range auths {
		// Create the KV secret in Vault.
		putKV(t, secrets[idx])
		// Create the VSS object referencing the object in Vault.
		require.Nil(t, crdClient.Create(ctx, secrets[idx]))
		// Assert that the Kube secret exists + has correct Data.
		assertSync(t, secrets[idx])

		deleteKV(t, secrets[idx])
	}

	getTokenData := func(t *testing.T, accessor string) (map[string]interface{}, error) {
		t.Helper()

		resp, err := vClient.Logical().WriteWithContext(ctx, "auth/token/lookup-accessor", map[string]interface{}{"accessor": accessor})
		if err != nil || resp == nil {
			return nil, err
		}
		return resp.Data, nil
	}

	// Get all Vault token accessors that are created from the test by filtering for those that have only the default
	// and revocationK8sOutputs.PolicyName policies
	var testTokenAccessors []string
	resp, err := vClient.Logical().ListWithContext(ctx, "auth/token/accessors")
	require.NoError(t, err)
	require.NotNil(t, resp)

	accessors, ok := resp.Data["keys"].([]interface{})
	require.True(t, ok)

	for _, accessor := range accessors {
		tokenData, err := getTokenData(t, accessor.(string))
		if assert.NoError(t, err) {
			policies := tokenData["policies"].([]interface{})
			if len(policies) == 2 &&
				(policies[0] == outputs.PolicyName || policies[1] == outputs.PolicyName) {
				testTokenAccessors = append(testTokenAccessors, accessor.(string))
			}
		}
	}
	require.Len(t, testTokenAccessors, len(auths))

	exportKindLogs(t)
	// Uninstall vso resource
	terraform.Destroy(t, &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Targets:      []string{"helm_release.vault-secrets-operator"},
		Vars: map[string]interface{}{
			"k8s_vault_connection_address": testVaultAddress,
			"k8s_test_namespace":           testK8sNamespace,
			"k8s_config_context":           k8sConfigContext,
			"vault_kvv2_mount_path":        testKvv2MountPath,
			"operator_helm_chart_path":     chartPath,
		},
	})

	// Check if all test tokens have been revoked.
	retry.DoWithRetry(t, "waitForAllTestTokensToBeRevoked", 30, time.Second, func() (string, error) {
		var unrevoked []string
		for _, accessor := range testTokenAccessors {
			// expect to receive an error that contains "invalid accessor" when looking up the token using its accessor
			// as an indication that the token was successfully revoked
			_, err = getTokenData(t, accessor)
			if err == nil || !strings.Contains(err.Error(), "invalid accessor") {
				unrevoked = append(unrevoked, accessor)
			}
		}
		if len(unrevoked) > 0 {
			return "", fmt.Errorf("found tokens unrevoked accessors=%v", unrevoked)
		}

		return fmt.Sprintf("Tokens revoked successfully %v", testTokenAccessors), nil
	})
}
