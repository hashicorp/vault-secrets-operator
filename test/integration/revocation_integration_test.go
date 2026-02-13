// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

// TestRevocation tests the revocation logic on Helm uninstall
func TestRevocation(t *testing.T) {
	if !testWithHelm {
		t.Skipf("Helm only test, and testWithHelm=%t", testWithHelm)
	}

	t.Skip("Disabling until VAULT-20196 is resolved")

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

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "revocation/terraform"), tempDir)
	copyModulesDirT(t, tfDir)
	chartDestDir := copyChartDirT(t, tfDir)

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
			"operator_helm_chart_path":     chartDestDir,
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
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vaultauth-test-kubernetes-1",
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
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vaultauth-test-kubernetes-2",
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
		if !testInParallel {
			exportKindLogsT(t)
		}

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
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultAuthRef: a.Name,
					Namespace:    testVaultNamespace,
					VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
						Mount: testKvv2MountPath,
						Type:  consts.KVSecretTypeV2,
						Path:  dest,
					},
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

	// Get all Vault token secrets of the test auth objects
	var secretList corev1.SecretList
	labels := ctrlclient.MatchingLabels{"app.kubernetes.io/component": "client-cache-storage"}
	opts := []ctrlclient.ListOption{
		ctrlclient.InNamespace(operatorNS),
		labels,
	}
	crdClient.List(ctx, &secretList, opts...)
	var testTokenSecrets []corev1.Secret
	for _, item := range secretList.Items {
		fmt.Printf("item %s %+v", item.Name, item.Labels)
		for _, auth := range auths {
			if val, ok := item.Labels["auth/UID"]; ok && val == string(auth.UID) {
				testTokenSecrets = append(testTokenSecrets, item)
				break
			}
		}
	}
	require.Len(t, testTokenSecrets, len(auths))

	if !testInParallel {
		exportKindLogsT(t)
	}

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

	// Check if all test tokens were revoked.
	for _, accessor := range testTokenAccessors {
		// expect to receive an error that contains "invalid accessor" when looking up the token using its accessor
		// as an indication that the token was successfully revoked
		_, err = getTokenData(t, accessor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid accessor")
	}

	// Check if Vault token secrets were deleted. Get should return an error
	for _, tokenSecret := range testTokenSecrets {
		err := crdClient.Get(ctx, ctrlclient.ObjectKey{
			Namespace: operatorNS,
			Name:      tokenSecret.Name,
		}, &tokenSecret)
		require.Error(t, err)
	}
}
