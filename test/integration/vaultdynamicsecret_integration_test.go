// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

type dynamicK8SOutputs struct {
	NamePrefix              string `json:"name_prefix"`
	Namespace               string `json:"namespace"`
	K8sNamespace            string `json:"k8s_namespace"`
	K8sConfigContext        string `json:"k8s_config_context"`
	AuthMount               string `json:"auth_mount"`
	AuthPolicy              string `json:"auth_policy"`
	AuthRole                string `json:"auth_role"`
	DBRole                  string `json:"db_role"`
	DBRoleStatic            string `json:"db_role_static"`
	DefaultLeaseTTLSeconds  int    `json:"default_lease_ttl_seconds"`
	DBRoleStaticUser        string `json:"db_role_static_user"`
	StaticRotationPeriod    int    `json:"static_rotation_period"`
	NonRenewableK8STokenTTL int    `json:"non_renewable_k8s_token_ttl"`
	// should always be non-renewable
	K8SSecretPath  string `json:"k8s_secret_path"`
	K8SSecretRole  string `json:"k8s_secret_role"`
	DBPath         string `json:"db_path"`
	TransitPath    string `json:"transit_path"`
	TransitKeyName string `json:"transit_key_name"`
	TransitRef     string `json:"transit_ref"`
}

func TestVaultDynamicSecret(t *testing.T) {
	if testInParallel {
		t.Parallel()
	}

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultdynamicsecret/terraform"), tempDir)
	copyModulesDirT(t, tfDir)

	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context":  k8sConfigContext,
			"k8s_vault_namespace": k8sVaultNamespace,
			// the service account is created in test/integration/infra/main.tf
			"k8s_vault_service_account":  "vault",
			"name_prefix":                "vds",
			"vault_address":              os.Getenv("VAULT_ADDRESS"),
			"vault_token":                os.Getenv("VAULT_TOKEN"),
			"vault_token_period":         120,
			"vault_db_default_lease_ttl": 15,
		},
	}
	if entTests {
		tfOptions.Vars["vault_enterprise"] = true
	}

	tfOptions = setCommonTFOptions(t, tfOptions)
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if !skipCleanup {
			// Deletes the VaultAuthMethods/Connections.
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
	var auths []*secretsv1beta1.VaultAuth
	auths = append(auths, &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: operatorNS,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			Namespace: outputs.Namespace,
			Method:    "kubernetes",
			Mount:     outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	})

	create := func(o ctrlclient.Object) {
		require.Nil(t, crdClient.Create(ctx, o))
		created = append(created, o)
	}

	//for _, o := range conns {
	//	create(o)
	//}
	for _, o := range auths {
		create(o)
	}

	tests := []struct {
		name                 string
		authObj              *secretsv1beta1.VaultAuth
		rolloutRestartTarget secretsv1beta1.RolloutRestartTarget
		expected             map[string]int
		expectedStatic       map[string]int
		create               int
		createStatic         int
		createNonRenewable   int
		existing             int
	}{
		{
			name: "existing-only-rollout-restart-deployment",
			rolloutRestartTarget: secretsv1beta1.RolloutRestartTarget{
				Kind: "Deployment",
			},
			existing: 5,
			expected: map[string]int{
				helpers.SecretDataKeyRaw: 100,
				"username":               51,
				"password":               20,
			},
		},
		{
			name: "existing-only-rollout-restart-argo-rollout",
			rolloutRestartTarget: secretsv1beta1.RolloutRestartTarget{
				Kind: "argo.Rollout",
			},
			existing: 1,
			expected: map[string]int{
				helpers.SecretDataKeyRaw: 100,
				"username":               51,
				"password":               20,
			},
		},
		{
			name: "existing-only-rollout-restart-argo-rollout-v1alpha1",
			rolloutRestartTarget: secretsv1beta1.RolloutRestartTarget{
				Kind:       "argo.Rollout",
				APIVersion: "argoproj.io/v1alpha1",
			},
			existing: 5,
			expected: map[string]int{
				helpers.SecretDataKeyRaw: 100,
				"username":               51,
				"password":               20,
			},
		},
		{
			name: "create-only-rollout-restart-deployment",
			rolloutRestartTarget: secretsv1beta1.RolloutRestartTarget{
				Kind: "Deployment",
			},
			create: 5,
			expected: map[string]int{
				helpers.SecretDataKeyRaw: 100,
				"username":               51,
				"password":               20,
			},
		},
		{
			name: "mixed-rollout-restart-deployment",
			rolloutRestartTarget: secretsv1beta1.RolloutRestartTarget{
				Kind: "Deployment",
			},
			create:             5,
			createStatic:       5,
			createNonRenewable: 5,
			existing:           5,
			expected: map[string]int{
				helpers.SecretDataKeyRaw: 100,
				"username":               51,
				"password":               20,
			},
			expectedStatic: map[string]int{
				// the _raw, last_vault_rotation, and ttl keys are only tested for their presence in
				// assertDynamicSecret, so no need to include them here.
				"password":        20,
				"rotation_period": 2,
				"username":        24,
			},
		},
		{
			name:         "create-static",
			createStatic: 5,
			expectedStatic: map[string]int{
				// the _raw, last_vault_rotation, and ttl keys are only tested for their presence in
				// assertDynamicSecret, so no need to include them here.
				"password":        20,
				"rotation_period": 2,
				"username":        24,
			},
		},
		{
			name:               "create-non-renewable",
			createNonRenewable: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objsCreated []*secretsv1beta1.VaultDynamicSecret
			var otherObjsCreated []ctrlclient.Object

			t.Cleanup(func() {
				if !skipCleanup {
					for _, obj := range objsCreated {
						assert.NoError(t, crdClient.Delete(ctx, obj))
					}
					for _, obj := range otherObjsCreated {
						assert.NoError(t, crdClient.Delete(ctx, obj))
					}
				}
			})

			// pre-created secrets test
			for idx := 0; idx < tt.existing; idx++ {
				dest := fmt.Sprintf("%s-dest-exists-%d", tt.name, idx)
				s := &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
				}
				require.NoError(t, crdClient.Create(ctx, s))
				otherObjsCreated = append(otherObjsCreated, s)
				vdsObj := &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.DBPath,
						Path:      "creds/" + outputs.DBRole,
						Revoke:    true,
						Destination: secretsv1beta1.Destination{
							Name:   dest,
							Create: false,
						},
					},
				}
				rolloutRestartObjKey := ctrlclient.ObjectKey{
					Namespace: outputs.K8sNamespace,
					Name:      dest,
				}
				rolloutRestartObj := createRolloutRestartObj(t, ctx, crdClient,
					rolloutRestartObjKey,
					tt.rolloutRestartTarget,
				)

				otherObjsCreated = append(otherObjsCreated, rolloutRestartObj)

				tt.rolloutRestartTarget.Name = rolloutRestartObjKey.Name
				vdsObj.Spec.RolloutRestartTargets = []secretsv1beta1.RolloutRestartTarget{
					tt.rolloutRestartTarget,
				}

				assert.NoError(t, crdClient.Create(ctx, vdsObj))
				objsCreated = append(objsCreated, vdsObj)
			}

			// create secrets tests
			for idx := 0; idx < tt.create; idx++ {
				dest := fmt.Sprintf("%s-create-%d", tt.name, idx)
				vdsObj := &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.DBPath,
						Path:      "creds/" + outputs.DBRole,
						Revoke:    true,
						Destination: secretsv1beta1.Destination{
							Name:   dest,
							Create: true,
						},
					},
				}
				rolloutRestartObjKey := ctrlclient.ObjectKey{
					Namespace: outputs.K8sNamespace,
					Name:      dest,
				}
				rolloutRestartObj := createRolloutRestartObj(t, ctx, crdClient,
					rolloutRestartObjKey,
					tt.rolloutRestartTarget,
				)
				otherObjsCreated = append(otherObjsCreated, rolloutRestartObj)

				tt.rolloutRestartTarget.Name = rolloutRestartObjKey.Name
				vdsObj.Spec.RolloutRestartTargets = []secretsv1beta1.RolloutRestartTarget{
					tt.rolloutRestartTarget,
				}

				assert.NoError(t, crdClient.Create(ctx, vdsObj))
				objsCreated = append(objsCreated, vdsObj)
			}

			for idx := 0; idx < tt.createStatic; idx++ {
				dest := fmt.Sprintf("%s-create-static-creds-%d", tt.name, idx)
				vdsObj := &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Namespace:        outputs.Namespace,
						Mount:            outputs.DBPath,
						Path:             "static-creds/" + outputs.DBRoleStatic,
						AllowStaticCreds: true,
						Revoke:           false,
						Destination: secretsv1beta1.Destination{
							Name:   dest,
							Create: true,
						},
					},
				}

				assert.NoError(t, crdClient.Create(ctx, vdsObj))
				objsCreated = append(objsCreated, vdsObj)
			}

			for idx := 0; idx < tt.createNonRenewable; idx++ {
				dest := fmt.Sprintf("%s-create-nr-creds-%d", tt.name, idx)
				vdsObj := &secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: v1.ObjectMeta{
						Namespace: outputs.K8sNamespace,
						Name:      dest,
						// used to denote the expected secret "type"
						Annotations: map[string]string{
							"non-renewable": "true",
						},
					},
					Spec: secretsv1beta1.VaultDynamicSecretSpec{
						Namespace: outputs.Namespace,
						Mount:     outputs.K8SSecretPath,
						Params: map[string]string{
							"kubernetes_namespace": outputs.K8sNamespace,
						},
						RenewalPercent: 1,
						Path:           "creds/" + outputs.K8SSecretRole,
						Destination: secretsv1beta1.Destination{
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

				expected := tt.expected
				var expectedPresentOnly []string
				if obj.Spec.AllowStaticCreds {
					nameFmt = "static-" + nameFmt
					expected = tt.expectedStatic
					expectedPresentOnly = append(expectedPresentOnly,
						helpers.SecretDataKeyRaw,
						"last_vault_rotation",
						"ttl",
					)
				} else if _, ok := obj.Annotations["non-renewable"]; ok {
					nameFmt = "non-renewable-" + nameFmt
					// the non-renewable test checks that all data keys are populated, so we expect
					// the expected map to be empty.
					expected = make(map[string]int)
					expectedPresentOnly = append(expectedPresentOnly,
						helpers.SecretDataKeyRaw,
						"service_account_name",
						"service_account_namespace",
						"service_account_token",
					)
				}

				count++
				t.Run(fmt.Sprintf(nameFmt, idx), func(t *testing.T) {
					obj := obj
					expected := maps.Clone(expected)
					expectedPresentOnly := expectedPresentOnly
					t.Parallel()

					assertDynamicSecret(t, nil, tfOptions.MaxRetries, tfOptions.TimeBetweenRetries, obj,
						expected, expectedPresentOnly...)
					if t.Failed() {
						return
					}

					objKey := ctrlclient.ObjectKeyFromObject(obj)
					var vdsObjFinal *secretsv1beta1.VaultDynamicSecret
					require.NoError(t, backoff.Retry(
						func() error {
							var vdsObj secretsv1beta1.VaultDynamicSecret
							require.NoError(t, crdClient.Get(ctx, objKey, &vdsObj))
							if vdsObj.Spec.AllowStaticCreds {
								if vdsObj.Status.StaticCredsMetaData.LastVaultRotation < 1 {
									return fmt.Errorf("expected LastVaultRotation to be greater than 0 on %s, actual=%d",
										objKey, vdsObj.Status.StaticCredsMetaData.LastVaultRotation)
								}
							} else {
								if vdsObj.Status.SecretLease.ID == "" {
									return fmt.Errorf("expected lease ID to be set on %s", objKey)
								}
							}
							vdsObjFinal = &vdsObj
							return nil
						},
						backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10),
					))

					assert.Equal(t,
						vdsObjFinal.GetGeneration(), vdsObjFinal.Status.LastGeneration,
						"expected Status.LastGeneration")
					assert.NotEmpty(t, vdsObjFinal.Status.LastRuntimePodUID)
					assert.NotEmpty(t, vdsObjFinal.Status.LastRenewalTime)

					var skipRemediationTests bool
					// for a 1s interval between tries
					var maxRetriesForRemediation uint64
					if vdsObjFinal.Spec.AllowStaticCreds {
						assert.Empty(t, vdsObjFinal.Status.SecretLease.ID)
						maxRetriesForRemediation = uint64(outputs.StaticRotationPeriod)
					} else {
						assert.NotEmpty(t, vdsObjFinal.Status.SecretLease.ID)
						var ttl float64
						if vdsObjFinal.Status.SecretLease.Renewable {
							ttl = float64(outputs.DefaultLeaseTTLSeconds)
						} else {
							skipRemediationTests = true
							ttl = float64(outputs.NonRenewableK8STokenTTL)
						}

						if !skipRemediationTests {
							maxRetriesForRemediation = uint64(ttl*.10 + (ttl * (float64(vdsObjFinal.Spec.RenewalPercent) / 100)))
						}
					}

					assertLastRuntimePodUID(t, ctx, crdClient, operatorNS, vdsObjFinal)
					assertDynamicSecretRotation(t, ctx, crdClient, vdsObjFinal)

					if vdsObjFinal.Spec.Destination.Create && !t.Failed() {
						if !skipRemediationTests {
							// must be called before assertDynamicSecretNewGeneration, since
							// that function changes the destination secret's name.
							assertRemediationOnDestinationDeletion(t, ctx, crdClient, obj, time.Millisecond*500, maxRetriesForRemediation*3)
						}
						if !t.Failed() {
							assertDynamicSecretNewGeneration(t, ctx, crdClient, vdsObjFinal)
						}
					}
				})
			}
			assert.Greater(t, count, 0, "no tests were run")
		})
	}
	// Get a Vault client, so we can validate that all leases have been removed.
	cfg := api.DefaultConfig()
	cfg.Address = vaultAddr
	c, err := api.NewClient(cfg)
	assert.NoError(t, err)
	c.SetToken(vaultToken)
	if !skipCleanup {
		// Ensure that all leases have been revoked.
		retry.DoWithRetry(t, "waitForAllLeasesToBeRevoked", 30, time.Second, func() (string, error) {
			resp, err := c.Logical().ListWithContext(ctx, fmt.Sprintf("sys/leases/lookup/%s/creds/%s", outputs.DBPath, outputs.DBRole))
			if err != nil {
				return "", err
			}
			if resp == nil {
				return "", nil
			}
			keys := resp.Data["keys"].([]interface{})
			if len(keys) > 0 {
				// Print out the lease ids that are still found to make debugging easier.
				return "", fmt.Errorf("leases still found: %v", keys)
			}
			return "", nil
		})
	}
}

func assertLastRuntimePodUID(t *testing.T,
	ctx context.Context, client ctrlclient.Client,
	operatorNS string, vdsObj *secretsv1beta1.VaultDynamicSecret,
) {
	var pods corev1.PodList
	assert.NoError(t, client.List(ctx, &pods, ctrlclient.InNamespace(operatorNS),
		ctrlclient.MatchingLabels{
			"control-plane": "controller-manager",
		},
	))
	if !assert.NotNil(t, pods) {
		return
	}
	assert.Equal(t, 1, len(pods.Items))
	assert.Equal(t, pods.Items[0].UID, vdsObj.Status.LastRuntimePodUID)
}

// assertDynamicSecretNewGeneration tests that an update to vdsObjOrig results in
// a full secret rotation.
func assertDynamicSecretNewGeneration(t *testing.T,
	ctx context.Context, client ctrlclient.Client,
	vdsObjOrig *secretsv1beta1.VaultDynamicSecret,
) {
	t.Helper()

	objKey := ctrlclient.ObjectKeyFromObject(vdsObjOrig)

	// try and update the object, sometimes there are update races, so we want to
	// retry this operation.
	err := backoff.RetryNotify(
		func() error {
			var obj secretsv1beta1.VaultDynamicSecret
			if err := client.Get(ctx, objKey, &obj); err != nil {
				return backoff.Permanent(err)
			}

			obj.Spec.Destination.Name = vdsObjOrig.Spec.Destination.Name + "-new"
			if err := client.Update(ctx, &obj); err != nil {
				return err
			}
			return nil
		},
		backoff.WithMaxRetries(
			backoff.NewConstantBackOff(time.Millisecond*500),
			4),
		func(err error, d time.Duration) {
			t.Logf(
				"Retrying client.Update() of %s, err=%s, delay=%s", objKey, err, d)
		},
	)

	if !assert.NoError(t, err) {
		return
	}

	// wait for the object to be reconciled
	err = backoff.RetryNotify(func() error {
		var obj secretsv1beta1.VaultDynamicSecret
		if err := client.Get(ctx, objKey, &obj); err != nil {
			return backoff.Permanent(err)
		}
		if obj.GetGeneration() < vdsObjOrig.GetGeneration() {
			return backoff.Permanent(fmt.Errorf(
				"unexpected, the updated's generation was less than the original's"))
		}

		if obj.GetGeneration() == vdsObjOrig.GetGeneration() {
			return fmt.Errorf("generation has not been updated")
		}

		if obj.GetGeneration() != obj.Status.LastGeneration {
			return fmt.Errorf(
				"last generation %d, does not match current %d: obj=%#v",
				obj.Status.LastGeneration, obj.GetGeneration(), obj)
		}

		// check updated destination secret exists
		_, exists, err := helpers.GetSyncableSecret(ctx, client, &obj)
		if err != nil {
			return backoff.Permanent(err)
		}

		assert.True(t, exists)
		return nil
	},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 20),
		func(err error, d time.Duration) {
			if withExtraVerbosity {
				t.Logf(
					"Retrying wait reonciliation of %s, err=%s, delay=%s", objKey, err, d)
			}
		},
	)

	assert.NoError(t, err)
}

// assertDynamicSecretRotation revokes the lease of vdsObjFinal,
// then waits for the controller to rotate the secret..
func assertDynamicSecretRotation(t *testing.T, ctx context.Context,
	client ctrlclient.Client, vdsObj *secretsv1beta1.VaultDynamicSecret,
) {
	bo := backoff.NewConstantBackOff(time.Millisecond * 500)
	var maxTries uint64
	if !vdsObj.Spec.AllowStaticCreds {
		maxTries = uint64(vdsObj.Status.SecretLease.LeaseDuration * 2)
	} else {
		if !assert.Greater(t, vdsObj.Status.StaticCredsMetaData.RotationPeriod, int64(0)) {
			return
		}
		if !assert.NotEmpty(t, vdsObj.Status.SecretMAC) {
			return
		}
		maxTries = uint64(vdsObj.Status.StaticCredsMetaData.RotationPeriod * 4)
	}

	vClient, err := api.NewClient(api.DefaultConfig())
	if vdsObj.Spec.Namespace != "" {
		vClient.SetNamespace(vdsObj.Spec.Namespace)
	}
	if !assert.NoError(t, err) {
		return
	}
	// revoke the lease
	if !vdsObj.Spec.AllowStaticCreds {
		if !assert.NoError(t, vClient.Sys().Revoke(vdsObj.Status.SecretLease.ID)) {
			return
		}
	}

	// wait for the rotation
	if !assert.NoError(t, backoff.Retry(func() error {
		var o secretsv1beta1.VaultDynamicSecret
		if err := client.Get(ctx,
			ctrlclient.ObjectKeyFromObject(vdsObj), &o); err != nil {
			return backoff.Permanent(err)
		}
		if !o.Spec.AllowStaticCreds {
			if o.Status.SecretLease.ID == vdsObj.Status.SecretLease.ID {
				return fmt.Errorf("leased secret never rotated")
			}
		} else {
			var errs error
			if o.Status.StaticCredsMetaData.LastVaultRotation == vdsObj.Status.StaticCredsMetaData.LastVaultRotation {
				errs = errors.Join(errs, fmt.Errorf("static-creds LastVaultRotation not updated"))
			}
			if o.Status.SecretMAC == vdsObj.Status.SecretMAC {
				errs = errors.Join(errs, fmt.Errorf("static-creds SecretMAC not updated"))
			}
			return errs
		}
		return nil
	}, backoff.WithMaxRetries(bo, maxTries),
	)) {
		return
	}

	// check that all rollout-restarts completed successfully
	if len(vdsObj.Spec.RolloutRestartTargets) > 0 {
		fmt.Printf("=========before awaitRolloutRestarts")
		awaitRolloutRestarts(t, ctx, client,
			vdsObj, vdsObj.Spec.RolloutRestartTargets)
	}
}
