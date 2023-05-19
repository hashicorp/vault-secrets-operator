// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func TestVaultDynamicSecret(t *testing.T) {
	if testWithHelm {
		t.Skipf("Test is not compatiable with Helm")
	}
	testID := fmt.Sprintf("vds")
	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "vaultdynamicsecret/terraform"),
		tempDir,
		"terraform",
	)
	require.Nil(t, err)

	k8sConfigContext := os.Getenv("KIND_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}
	k8sOpts := &k8s.KubectlOptions{
		ContextName: k8sConfigContext,
		Namespace:   operatorNS,
	}
	kustomizeConfigPath := filepath.Join(kustomizeConfigRoot, "persistence-encrypted")
	deployOperatorWithKustomize(t, k8sOpts, kustomizeConfigPath)

	k8sDBSecretsCountFromTF := 5
	if v := os.Getenv("K8S_DB_SECRET_COUNT"); v != "" {
		count, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		k8sDBSecretsCountFromTF = count
	}
	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context":         k8sConfigContext,
			"name_prefix":                testID,
			"k8s_db_secret_count":        k8sDBSecretsCountFromTF,
			"vault_address":              os.Getenv("VAULT_ADDRESS"),
			"vault_token":                os.Getenv("VAULT_TOKEN"),
			"vault_token_period":         120,
			"vault_db_default_lease_ttl": 30,
		},
	}
	if entTests {
		tfOptions.Vars["vault_enterprise"] = true
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if !skipCleanup {
			exportKindLogs(t)

			// Clean up resources with "terraform destroy" at the end of the test.
			terraform.Destroy(t, tfOptions)
			os.RemoveAll(tempDir)

			// Undeploy Kustomize
			k8s.KubectlDeleteFromKustomize(t, k8sOpts, kustomizeConfigPath)
		} else {
			t.Logf("Skipping cleanup, tfdir=%s", tfDir)
		}
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, tfOptions)

	if skipCleanup {
		// save vars to re-run terraform, useful when SKIP_CLEANUP is set.
		b, err := json.Marshal(tfOptions.Vars)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(tfOptions.TerraformDir, "terraform.tfvars.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.Nil(t, err)

	var outputs dynamicK8SOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	// Set the secrets in vault to be synced to kubernetes
	// vClient := getVaultClient(t, testVaultNamespace)
	// Create a VaultConnection CR
	conns := []*secretsv1alpha1.VaultConnection{
		// Create the default VaultConnection CR in the Operator's namespace
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.NameDefault,
				Namespace: operatorNS,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}
	auths := []*secretsv1alpha1.VaultAuth{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.NameDefault,
				Namespace: operatorNS,
			},
			Spec: secretsv1alpha1.VaultAuthSpec{
				Namespace: outputs.Namespace,
				Method:    "kubernetes",
				Mount:     outputs.AuthMount,
				Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
					Role:           outputs.AuthRole,
					ServiceAccount: "default",
					TokenAudiences: []string{"vault"},
				},
			},
		},
	}

	create := func(o ctrlclient.Object) {
		require.Nil(t, crdClient.Create(ctx, o))
		created = append(created, o)
	}

	for _, o := range conns {
		create(o)
	}
	for _, o := range auths {
		create(o)
	}

	tests := []struct {
		name     string
		authObj  *secretsv1alpha1.VaultAuth
		expected map[string]int
		create   int
		existing []string
	}{
		{
			name:     "existing-only",
			existing: outputs.K8sDBSecrets,
			authObj:  auths[0],
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
		},
		{
			name:    "create-only",
			create:  5,
			authObj: auths[0],
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
		},
		{
			name:     "mixed",
			create:   5,
			existing: outputs.K8sDBSecrets,
			authObj:  auths[0],
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objsCreated []*secretsv1alpha1.VaultDynamicSecret

			t.Cleanup(func() {
				if !skipCleanup {
					for _, obj := range objsCreated {
						assert.NoError(t, crdClient.Delete(ctx, obj))
					}
				}
			})
			// pre-created secrets test
			for idx, dest := range tt.existing {
				vdsObj := &secretsv1alpha1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
					Spec: secretsv1alpha1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.DBPath,
						Path:      "creds/" + outputs.DBRole,
						Revoke:    true,
						Destination: secretsv1alpha1.Destination{
							Name:   dest,
							Create: false,
						},
					},
				}
				if idx == 0 {
					vdsObj.Spec.RolloutRestartTargets = []secretsv1alpha1.RolloutRestartTarget{
						{
							Kind: "Deployment",
							Name: outputs.DeploymentName,
						},
					}
				}

				assert.NoError(t, crdClient.Create(ctx, vdsObj))
				objsCreated = append(objsCreated, vdsObj)
			}

			// create secrets tests
			for idx := 0; idx < tt.create; idx++ {
				dest := fmt.Sprintf("%s-create-%d", tt.name, idx)
				vdsObj := &secretsv1alpha1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
					Spec: secretsv1alpha1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.DBPath,
						Path:      "creds/" + outputs.DBRole,
						Revoke:    true,
						Destination: secretsv1alpha1.Destination{
							Name:   dest,
							Create: true,
						},
					},
				}

				assert.NoError(t, crdClient.Create(ctx, vdsObj))
				objsCreated = append(objsCreated, vdsObj)
			}

			var count int
			for idx, obj := range objsCreated {
				nameFmt := "existing-dest-%d"
				if obj.Spec.Destination.Create {
					nameFmt = "create-dest-%d"
				}
				count++
				t.Run(fmt.Sprintf(nameFmt, idx), func(t *testing.T) {
					// capture obj for parallel test
					obj := obj
					t.Parallel()
					assertDynamicSecret(t,
						tfOptions.MaxRetries,
						tfOptions.TimeBetweenRetries,
						obj,
						tt.expected,
					)

					if t.Failed() {
						return
					}

					objKey := ctrlclient.ObjectKeyFromObject(obj)
					var vdsObjFinal secretsv1alpha1.VaultDynamicSecret
					require.NoError(t, backoff.Retry(
						func() error {
							var vdsObj secretsv1alpha1.VaultDynamicSecret
							require.NoError(t, crdClient.Get(ctx, objKey, &vdsObj))
							if vdsObj.Status.SecretLease.ID == "" {
								return fmt.Errorf("expected lease ID to be set on %s", objKey)
							}
							vdsObjFinal = vdsObj
							return nil
						},
						backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10),
					))

					assert.NotEmpty(t, vdsObjFinal.Status.LastRuntimePodUID)
					assert.NotEmpty(t, vdsObjFinal.Status.LastRenewalTime)
					assert.NotEmpty(t, vdsObjFinal.Status.SecretLease.ID)

					var pods corev1.PodList
					assert.NoError(t, crdClient.List(ctx, &pods, ctrlclient.InNamespace(operatorNS),
						ctrlclient.MatchingLabels{
							"control-plane": "controller-manager",
						},
					))
					require.Equal(t, 1, len(pods.Items))
					assert.Equal(t, pods.Items[0].UID, vdsObjFinal.Status.LastRuntimePodUID)

					assertDynamicSecretRotation(t, ctx, crdClient, &vdsObjFinal)
				})
			}
			assert.Greater(t, count, 0, "no tests were run")
		})
	}
	// Delete remaining CRDs which were created, and then validate that the leases are all revoked.
	for _, c := range created {
		// test that the custom resources can be deleted before tf destroy
		// removes the k8s namespace
		assert.Nil(t, crdClient.Delete(ctx, c))
	}
	// Get a Vault client so we can validate that all leases have been removed.
	cfg := api.DefaultConfig()
	cfg.Address = vaultAddr
	c, err := api.NewClient(cfg)
	assert.NoError(t, err)
	c.SetToken(vaultToken)
	// Check to be sure all leases have been revoked.
	retry.DoWithRetry(t, "waitForAllLeasesToBeRevoked", 30, time.Second, func() (string, error) {
		// ensure that all leases have been revoked.
		resp, err := c.Logical().ListWithContext(ctx, fmt.Sprintf("sys/leases/lookup/%s/creds/%s", outputs.DBPath, outputs.DBRole))
		if err != nil {
			return "", err
		}
		if resp == nil {
			return "", nil
		}
		keys := resp.Data["keys"].([]interface{})
		if len(keys) > 0 {
			return "", fmt.Errorf("Leases still found: %d", len(keys))
		}
		return "", nil
	})
}

// assertDynamicSecretRotation revokes the lease of vdsObjFinal,
// then waits for the controller to rotate the secret..
func assertDynamicSecretRotation(t *testing.T, ctx context.Context,
	client ctrlclient.Client, vdsObj *secretsv1alpha1.VaultDynamicSecret,
) {
	vClient, err := api.NewClient(api.DefaultConfig())
	if vdsObj.Spec.Namespace != "" {
		vClient.SetNamespace(vdsObj.Spec.Namespace)
	}
	if !assert.NoError(t, err) {
		return
	}
	// revoke the lease
	if !assert.NoError(t, vClient.Sys().Revoke(vdsObj.Status.SecretLease.ID)) {
		return
	}

	// wait for the rotation
	if !assert.NoError(t, backoff.Retry(func() error {
		var o secretsv1alpha1.VaultDynamicSecret
		if err := client.Get(ctx,
			ctrlclient.ObjectKeyFromObject(vdsObj), &o); err != nil {
			return backoff.Permanent(err)
		}
		if o.Status.SecretLease.ID == vdsObj.Status.SecretLease.ID {
			return fmt.Errorf("secret never rotated")
		}
		return nil
	}, backoff.WithMaxRetries(
		backoff.NewConstantBackOff(time.Millisecond*500),
		uint64(vdsObj.Status.SecretLease.LeaseDuration*2)),
	)) {
		return
	}

	// check that all rollout-restarts completed successfully
	if len(vdsObj.Spec.RolloutRestartTargets) > 0 {
		waitForRolloutRestartsAndAssertRollout(t, ctx, client,
			vdsObj, vdsObj.Spec.RolloutRestartTargets)
	}
}
