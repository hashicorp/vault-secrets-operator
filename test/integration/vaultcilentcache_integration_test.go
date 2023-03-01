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

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/gruntwork-io/terratest/modules/retry"

	"github.com/gruntwork-io/terratest/modules/k8s"

	"github.com/hashicorp/vault-secrets-operator/internal/common"

	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

func TestVaultClientCache(t *testing.T) {
	if os.Getenv("DEPLOY_OPERATOR_WITH_HELM") != "" {
		t.Skipf("Test is not compatiable with Helm")
	}

	testID := fmt.Sprintf("vcc")
	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	common.OperatorNamespace = operatorNS

	crdClient := getCRDClient(t)
	var created []ctrlclient.Object
	ctx := context.Background()

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "vaultdynamicsecret/terraform"),
		tempDir,
		"terraform",
	)
	require.Nil(t, err)

	k8sDBSecretsCountFromTF := 0
	if v := os.Getenv("K8S_DB_SECRET_COUNT"); v != "" {
		count, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		k8sDBSecretsCountFromTF = count
	}

	k8sDBSecretsToCreate := 1
	if v := os.Getenv("K8S_DB_SECRET_COUNT_CREATE"); v != "" {
		count, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		k8sDBSecretsToCreate = count
	}
	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context":         "kind-" + clusterName,
			"name_prefix":                testID,
			"k8s_db_secret_count":        k8sDBSecretsCountFromTF,
			"vault_address":              os.Getenv("VAULT_ADDRESS"),
			"vault_token":                os.Getenv("VAULT_TOKEN"),
			"vault_token_period":         300, // shouldn't really be set for less than 60 for this test.
			"vault_db_default_lease_ttl": 60,
			"operator_namespace":         operatorNS,
		},
	}
	if entTests := os.Getenv("ENT_TESTS"); entTests != "" {
		tfOptions.Vars["vault_enterprise"] = true
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

	tfOptions.MaxRetries = 120
	tfOptions.TimeBetweenRetries = 500 * time.Millisecond

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if !skipCleanup {
			for idx := len(created) - 1; idx >= 0; idx-- {
				// test that the custom resources can be deleted before tf destroy
				// removes the k8s namespace
				assert.Nil(t, crdClient.Delete(ctx, created[idx]))
			}
			// Clean up resources with "terraform destroy" at the end of the test.
			terraform.Destroy(t, tfOptions)
			os.RemoveAll(tempDir)
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
		if err := os.WriteFile(filepath.Join(tfOptions.TerraformDir, "terraform.tfvars.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.Nil(t, err)

	var outputs dynamicK8SOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	labels := map[string]string{
		"integration-test": t.Name(),
	}

	// Set the secrets in vault to be synced to kubernetes
	// vClient := getVaultClient(t, testVaultNamespace)
	// Create a VaultConnection CR
	conns := []*secretsv1alpha1.VaultConnection{
		// Create the default VaultConnection CR in the Operator's namespace
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.NameDefault,
				Namespace: operatorNS,
				Labels:    labels,
			},
			Spec: secretsv1alpha1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}
	for _, c := range conns {
		require.Nil(t, crdClient.Create(ctx, c))
		created = append(created, c)
	}

	kustomizeConfigRoot := filepath.Join(testRoot, "..", "..", "config")
	st, err := os.Stat(kustomizeConfigRoot)
	require.NoError(t, err, "failed to stat %s", kustomizeConfigRoot)
	require.True(t, st.IsDir(), "%s is not a directory", kustomizeConfigRoot)

	tests := []struct {
		name             string
		expected         map[string]int
		s                *secretsv1alpha1.VaultDynamicSecret
		auth             *secretsv1alpha1.VaultAuth
		ss               []*secretsv1alpha1.VaultDynamicSecret
		persistenceModel string
	}{
		{
			name:             "default",
			persistenceModel: "default",
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
			auth: &secretsv1alpha1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      consts.NameDefault,
					Namespace: operatorNS,
					Labels:    labels,
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					Namespace: outputs.Namespace,
					Method:    "kubernetes",
					Mount:     outputs.AuthMount,
					// VaultTransitRef: outputs.TransitRef,
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						Role:           outputs.AuthRole,
						ServiceAccount: "default",
						TokenAudiences: []string{"vault"},
					},
				},
			},
		},
		{
			name:             "persistence-unencrypted",
			persistenceModel: "persistence-unencrypted",
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
			auth: &secretsv1alpha1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      consts.NameDefault,
					Namespace: operatorNS,
					Labels:    labels,
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					Namespace: outputs.Namespace,
					Method:    "kubernetes",
					Mount:     outputs.AuthMount,
					// VaultTransitRef: outputs.TransitRef,
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						Role:           outputs.AuthRole,
						ServiceAccount: "default",
						TokenAudiences: []string{"vault"},
					},
				},
			},
		},
		{
			name:             "persistence-encrypted",
			persistenceModel: "persistence-encrypted",
			expected: map[string]int{
				"_raw":     100,
				"username": 51,
				"password": 20,
			},
			auth: &secretsv1alpha1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      consts.NameDefault,
					Namespace: operatorNS,
					Labels:    labels,
				},
				Spec: secretsv1alpha1.VaultAuthSpec{
					Namespace:       outputs.Namespace,
					Method:          "kubernetes",
					Mount:           outputs.AuthMount,
					VaultTransitRef: outputs.TransitRef,
					Kubernetes: &secretsv1alpha1.VaultAuthConfigKubernetes{
						Role:           outputs.AuthRole,
						ServiceAccount: "default",
						TokenAudiences: []string{"vault"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sOpts := &k8s.KubectlOptions{
				ContextName: outputs.K8sConfigContext,
			}

			configPath := filepath.Join(kustomizeConfigRoot, tt.persistenceModel)
			k8s.KubectlApplyFromKustomize(t, k8sOpts, configPath)
			k8sOpts.Namespace = operatorNS
			retry.DoWithRetry(t, "waitOperatorPodReady", 30, time.Millisecond*500, func() (string, error) {
				return "", k8s.RunKubectlE(t, k8sOpts,
					"wait", "--for=condition=Ready",
					"--timeout=2m", "pod", "-l", "control-plane=controller-manager")
			},
			)

			t.Cleanup(func() {
				assert.NoError(t, crdClient.Delete(ctx, tt.auth))
			})

			assert.Nil(t, crdClient.Create(ctx, tt.auth))

			for idx := 0; idx < k8sDBSecretsToCreate; idx++ {
				dest := fmt.Sprintf("%s-%s-%d", outputs.NamePrefix, tt.name, idx)
				s := &secretsv1alpha1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
						Labels:    labels,
					},
					Spec: secretsv1alpha1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.DBPath,
						Role:      outputs.DBRole,
						Dest:      dest,
						Create:    true,
					},
				}

				t.Run(fmt.Sprintf("vds-%d", idx), func(t *testing.T) {
					assert.Nil(t, crdClient.Create(ctx, s))
					// created = append(created, s)
					// assert.Nil(t, crdClient.Create(ctx, a))
					// created = append(created, a)
					waitForDynamicSecret(t,
						tfOptions.MaxRetries,
						tfOptions.TimeBetweenRetries,
						s.Spec.Dest,
						s.Namespace,
						tt.expected,
					)

					assertVCC(t, outputs, tt.persistenceModel, ctx, crdClient, tt.auth, conns[0], s)
				})
			}
		})
	}
}

func assertVCC(t *testing.T, outputs dynamicK8SOutputs, persistenceModel string, ctx context.Context, client ctrlclient.Client, a *secretsv1alpha1.VaultAuth, c *secretsv1alpha1.VaultConnection,
	s *secretsv1alpha1.VaultDynamicSecret,
) {
	t.Helper()

	cacheKey, err := vault.GetClientCacheKeyFromObj(ctx, client, s)
	require.NoError(t, err, "could not get the cacheKey for %#v", s)

	var result secretsv1alpha1.VaultClientCacheList
	retry.DoWithRetry(t, "awaitVaultClientCache", 30, time.Second*1, func() (string, error) {
		var r secretsv1alpha1.VaultClientCacheList
		if err := client.List(ctx, &r, ctrlclient.MatchingLabels{
			"cacheKey": cacheKey,
		}); err != nil {
			return "", err
		}
		if len(r.Items) == 0 {
			return "", fmt.Errorf("none found")
		}
		result = r
		return "", nil
	})

	curAuth := &secretsv1alpha1.VaultAuth{}
	require.NoError(t, client.Get(ctx, ctrlclient.ObjectKeyFromObject(a), curAuth))

	require.Equal(t, 1, len(result.Items))
	vccFound := result.Items[0]
	assert.Equal(t, vccFound.GetName(), vault.NamePrefixVCC+cacheKey)
	assert.Equal(t, vccFound.GetNamespace(), common.OperatorNamespace)
	assert.Equal(t, curAuth.GetName(), vccFound.Spec.VaultAuthRef)
	assert.Equal(t, curAuth.GetNamespace(), vccFound.Spec.VaultAuthNamespace)
	assert.Equal(t, curAuth.Spec.Method, vccFound.Spec.VaultAuthMethod)
	assert.Equal(t, curAuth.GetGeneration(), vccFound.Spec.VaultAuthGeneration,
		"expected VaultAuth generation %v, actual %v", a.GetGeneration(), vccFound.Spec.VaultAuthGeneration)
	assert.Equal(t, curAuth.GetUID(), vccFound.Spec.VaultAuthUID)
	assert.Equal(t, c.GetUID(), vccFound.Spec.VaultConnectionUID)
	assert.Equal(t, c.GetGeneration(), vccFound.Spec.VaultConnectionGeneration)

	vccKey := ctrlclient.ObjectKey{
		Namespace: vccFound.Namespace,
		Name:      vccFound.Name,
	}
	var vccSecret corev1.Secret
	if persistenceModel == "persistence-unencrypted" || persistenceModel == "persistence-encrypted" {
		retry.DoWithRetry(t, "awaitCachedSecret", 30, time.Second*1,
			func() (string, error) {
				secKey := ctrlclient.ObjectKey{
					Namespace: vccFound.Namespace,
					Name:      vccFound.Status.CacheSecretRef,
				}

				if vccFound.Status.CacheSecretRef == "" {
					return "", fmt.Errorf("CacheSecretRef is empty, status=%#v", vccFound.Status)
				}

				if vccFound.Status.CacheSecretRef != "" {
					if err := client.Get(ctx, secKey, &vccSecret); err != nil {
						if !apierrors.IsNotFound(err) {
							return "", fmt.Errorf("failed to get %s, err=%w", secKey, err)
						}
					} else {
						return "", nil
					}
				}

				var vccObj secretsv1alpha1.VaultClientCache
				if err := client.Get(ctx, vccKey, &vccObj); err != nil {
					return "", err
				}

				vccFound = vccObj

				return "", fmt.Errorf("secret %q, not found", secKey)
			},
		)
	}

	if persistenceModel == "persistence-unencrypted" {
		expectedLabels := map[string]string{
			"cacheKey": cacheKey,
		}
		assert.Equal(t, expectedLabels, vccSecret.Labels)
	}

	if persistenceModel == "persistence-encrypted" {
		expectedLabels := map[string]string{
			//"canary":          "yellow",
			"cacheKey":        cacheKey,
			"encrypted":       "true",
			"vaultTransitRef": outputs.TransitRef,
		}
		assert.Equal(t, expectedLabels, vccSecret.Labels)
		// TODO: decrypt and verify Unmarshalling.
	}
}
