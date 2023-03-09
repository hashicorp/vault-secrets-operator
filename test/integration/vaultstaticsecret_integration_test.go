// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/k8s"
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
	if os.Getenv("DEPLOY_OPERATOR_WITH_HELM") != "" {
		t.Skipf("Test is not compatiable with Helm, temporarily disabled")
	}
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvMountPath := "kv-v1" + testID
	testKvv2MountPath := "kv-v2" + testID
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

	k8sConfigContext := "kind-" + clusterName
	k8sOpts := &k8s.KubectlOptions{
		ContextName: k8sConfigContext,
		Namespace:   operatorNS,
	}
	kustomizeConfigPath := filepath.Join(kustomizeConfigRoot, "default")
	if !deployOperatorWithHelm {
		// deploy the Operator with Kustomize
		deployOperatorWithKustomize(t, k8sOpts, kustomizeConfigPath)
	}

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"deploy_operator_via_helm":     deployOperatorWithHelm,
			"k8s_vault_connection_address": testVaultAddress,
			"k8s_test_namespace":           testK8sNamespace,
			"k8s_config_context":           "kind-" + clusterName,
			"vault_kv_mount_path":          testKvMountPath,
			"vault_kvv2_mount_path":        testKvv2MountPath,
			"operator_helm_chart_path":     chartPath,
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

		// Undeploy Kustomize
		if !deployOperatorWithHelm {
			k8s.KubectlDeleteFromKustomize(t, k8sOpts, kustomizeConfigPath)
		}
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
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

	// since each test case mutates the VSS object, we use this function to pass
	// it a new slice for the expected, existing tests.
	getExisting := func() []*secretsv1alpha1.VaultStaticSecret {
		return []*secretsv1alpha1.VaultStaticSecret{
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
					Destination: secretsv1alpha1.Destination{
						Name:   "secretkv",
						Create: false,
					},
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
					Namespace: testVaultNamespace,
					Mount:     testKvv2MountPath,
					Type:      "kv-v2",
					Name:      "secret",
					Destination: secretsv1alpha1.Destination{
						Name:   "secretkvv2",
						Create: false,
					},
					RefreshAfter: "5s",
				},
			},
		}
	}

	type expectedData struct {
		initial map[string]interface{}
		update  map[string]interface{}
	}

	tests := []struct {
		name     string
		existing []*secretsv1alpha1.VaultStaticSecret
		// expectedData maps to each vssObj in existing, so they need to be equal in length
		expectedExisting []expectedData
		create           int
	}{
		{
			name: "existing-only",
			expectedExisting: []expectedData{
				{
					initial: map[string]interface{}{"password": "grapejuice", "username": "breakfast", "time": "now"},
					update:  map[string]interface{}{"password": "orangejuice", "time": "morning"},
				},
				{
					initial: map[string]interface{}{"password": "applejuice", "username": "lunch", "time": "later"},
					update:  map[string]interface{}{"password": "cranberryjuice", "time": "evening"},
				},
			},
			existing: getExisting(),
		},
		{
			name:   "create-only",
			create: 10,
		},
		{
			name:   "mixed",
			create: 10,
			expectedExisting: []expectedData{
				{
					initial: map[string]interface{}{"username": "baz", "fruit": "banana"},
					update:  map[string]interface{}{"username": "baz", "fruit": "apple"},
				},
				{
					initial: map[string]interface{}{"username": "qux", "fruit": "chicle"},
					update:  map[string]interface{}{"username": "buz", "fruit": "mango"},
				},
			},
			existing: getExisting(),
		},
	}

	putKV := func(t *testing.T, vssObj *secretsv1alpha1.VaultStaticSecret, data map[string]interface{}) {
		switch vssObj.Spec.Type {
		case "kv-v1":
			require.NoError(t, vClient.KVv1(testKvMountPath).Put(ctx, vssObj.Spec.Name, data))
		case "kv-v2":
			_, err := vClient.KVv2(testKvv2MountPath).Put(ctx, vssObj.Spec.Name, data)
			require.NoError(t, err)
		default:
			t.Fatal("invalid KV type")
		}
	}

	deleteKV := func(t *testing.T, vssObj *secretsv1alpha1.VaultStaticSecret) {
		switch vssObj.Spec.Type {
		case "kv-v1":
			require.NoError(t, vClient.KVv1(testKvMountPath).Delete(ctx, vssObj.Spec.Name))
		case "kv-v2":
			require.NoError(t, vClient.KVv2(testKvv2MountPath).Delete(ctx, vssObj.Spec.Name))
		default:
			t.Fatal("invalid KV type")
		}
	}

	assertSync := func(t *testing.T, obj *secretsv1alpha1.VaultStaticSecret, expected expectedData, initial bool) {
		var data map[string]interface{}
		if initial {
			putKV(t, obj, expected.initial)
			require.NoError(t, crdClient.Create(ctx, obj))
			data = expected.initial
		} else {
			putKV(t, obj, expected.update)

			data = expected.update
		}

		secret, err := waitForSecretData(t, 30, 1*time.Second,
			obj.Spec.Destination.Name, obj.ObjectMeta.Namespace, data)
		if err == nil {
			assertSyncableSecret(t, obj,
				"secrets.hashicorp.com/v1alpha1",
				"VaultStaticSecret", secret)
		} else {
			assert.NoError(t, err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count int
			require.Equal(t, len(tt.existing), len(tt.expectedExisting))

			for idx, vssObj := range tt.existing {
				count++
				t.Run(fmt.Sprintf("%s-existing-%d", tt.name, idx), func(t *testing.T) {
					t.Cleanup(func() {
						assert.NoError(t, crdClient.Delete(ctx, vssObj))
					})
					assertSync(t, vssObj, tt.expectedExisting[idx], true)
					assertSync(t, vssObj, tt.expectedExisting[idx], false)
				})
			}

			// create
			for idx := 0; idx < tt.create; idx++ {
				for _, kvType := range []string{"kv-v1", "kv-v2"} {
					count++
					name := fmt.Sprintf("create-%s-%d", kvType, idx)
					t.Run(name, func(t *testing.T) {
						// capture idx and kvType for parallel test
						idx := idx
						kvType := kvType
						t.Parallel()

						mount := kvType + testID
						dest := fmt.Sprintf("create-%s-%d", kvType, idx)
						expected := expectedData{
							initial: map[string]interface{}{"dest-initial": dest},
							update:  map[string]interface{}{"dest-updated": dest},
						}
						vssObj := &secretsv1alpha1.VaultStaticSecret{
							ObjectMeta: v1.ObjectMeta{
								Name:      dest,
								Namespace: testK8sNamespace,
							},
							Spec: secretsv1alpha1.VaultStaticSecretSpec{
								VaultAuthRef: auths[0].ObjectMeta.Name,
								Namespace:    testVaultNamespace,
								Mount:        mount,
								Type:         kvType,
								Name:         dest,
								Destination: secretsv1alpha1.Destination{
									Name:   dest,
									Create: true,
								},
								RefreshAfter: "5s",
							},
						}

						t.Cleanup(func() {
							assert.NoError(t, crdClient.Delete(ctx, vssObj))
							deleteKV(t, vssObj)
						})

						assertSync(t, vssObj, expected, true)
						assertSync(t, vssObj, expected, false)
					})
				}
			}
			assert.Greater(t, count, 0, "no secrets were tested")
		})
	}
}
