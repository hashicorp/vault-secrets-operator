// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

type vpsK8SOutputs struct {
	NamePrefix        string `json:"name_prefix"`
	Namespace         string `json:"namespace"`
	K8sNamespace      string `json:"k8s_namespace"`
	K8sConfigContext  string `json:"k8s_config_context"`
	AuthMount         string `json:"auth_mount"`
	AuthPolicy        string `json:"auth_policy"`
	AuthRole          string `json:"auth_role"`
	PKIMount          string `json:"pki_mount"`
	PKIRole           string `json:"pki_role"`
	AppK8sNamespace   string `json:"app_k8s_namespace"`
	AppVaultNamespace string `json:"app_vault_namespace,omitempty"`
}

func TestVaultPKISecret(t *testing.T) {
	t.Skipf("Skipping test %s for VAULT-25273", t.Name())

	if testInParallel {
		t.Parallel()
	}

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")
	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultpkisecret/terraform"), tempDir)
	copyModulesDirT(t, tfDir)

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"name_prefix":                  "vps",
			"k8s_vault_connection_address": testVaultAddress,
			"k8s_config_context":           k8sConfigContext,
		},
	}
	if entTests {
		tfOptions.Vars["vault_enterprise"] = true
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	// Clean up resources with "terraform destroy" at the end of the test.
	t.Cleanup(func() {
		if !testInParallel {
			exportKindLogsT(t)
		}

		if !skipCleanup {
			for _, c := range created {
				// test that the custom resources can be deleted before tf destroy
				// removes the k8s namespace
				assert.Nil(t, crdClient.Delete(ctx, c))
			}

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

	var outputs vpsK8SOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))
	appK8sNamespace := outputs.AppK8sNamespace
	appVaultNamespace := outputs.AppVaultNamespace
	testVaultConnectionName := outputs.NamePrefix + "-app"
	testVaultAuthName := outputs.NamePrefix + "-app"

	// Create a VaultConnection CR
	testVaultConnection := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      testVaultConnectionName,
			Namespace: appK8sNamespace,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}
	require.NoError(t, crdClient.Create(ctx, testVaultConnection))
	created = append(created, testVaultConnection)

	// Create a VaultAuth CR
	testVaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      testVaultAuthName,
			Namespace: appK8sNamespace,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: testVaultConnectionName,
			Namespace:          appVaultNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	}

	require.NoError(t, crdClient.Create(ctx, testVaultAuth))
	created = append(created, testVaultAuth)

	// Create a VaultPKI CR to trigger the sync
	getExisting := func() []*secretsv1beta1.VaultPKISecret {
		return []*secretsv1beta1.VaultPKISecret{
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultpki-test-tenant-1",
					Namespace: appK8sNamespace,
				},
				Spec: secretsv1beta1.VaultPKISecretSpec{
					VaultAuthRef: testVaultAuthName,
					Namespace:    appVaultNamespace,
					Mount:        outputs.PKIMount,
					Role:         outputs.PKIRole,
					CommonName:   "test1.example.com",
					Format:       "pem",
					Revoke:       true,
					Clear:        true,
					ExpiryOffset: "1s",
					TTL:          "10s",
					AltNames:     []string{"alt1.example.com", "alt2.example.com"},
					URISans:      []string{"uri1.example.com", "uri2.example.com"},
					IPSans:       []string{"127.1.1.1", "127.0.0.1"},
					UserIDs:      []string{"12345", "67890"},
					Destination: secretsv1beta1.Destination{
						Name:   "pki1",
						Create: false,
					},
					RolloutRestartTargets: []secretsv1beta1.RolloutRestartTarget{
						{
							Kind: "Deployment",
							Name: "vso",
						},
					},
				},
			},
		}
	}

	tests := []struct {
		name       string
		existing   []*secretsv1beta1.VaultPKISecret
		create     int
		secretType corev1.SecretType
	}{
		{
			name:     "existing-only",
			existing: getExisting(),
		},
		{
			name:   "create-only",
			create: 1,
		},
		{
			name:     "mixed",
			existing: getExisting(),
			create:   5,
		},
		{
			name:       "create-tls",
			create:     2,
			secretType: corev1.SecretTypeTLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var toTest []*secretsv1beta1.VaultPKISecret
			for idx, obj := range tt.existing {
				name := fmt.Sprintf("%s-existing-%d", tt.name, idx)
				obj.Name = name
				toTest = append(toTest, obj)
			}

			for idx := 0; idx < tt.create; idx++ {
				dest := fmt.Sprintf("%s-create-%d", tt.name, idx)
				toTest = append(toTest, &secretsv1beta1.VaultPKISecret{
					ObjectMeta: v1.ObjectMeta{
						Name:      dest,
						Namespace: appK8sNamespace,
					},
					Spec: secretsv1beta1.VaultPKISecretSpec{
						VaultAuthRef: testVaultAuthName,
						Role:         outputs.PKIRole,
						Namespace:    appVaultNamespace,
						Mount:        outputs.PKIMount,
						CommonName:   fmt.Sprintf("%s.example.com", dest),
						Format:       "pem",
						Revoke:       true,
						ExpiryOffset: "2s",
						TTL:          "10s",
						AltNames:     []string{"alt1.example.com", "alt2.example.com"},
						URISans:      []string{"uri1.example.com", "uri2.example.com"},
						IPSans:       []string{"127.1.1.1", "127.0.0.1"},
						Destination: secretsv1beta1.Destination{
							Name:   dest,
							Create: true,
							Type:   tt.secretType,
						},
					},
				})
			}

			require.Equal(t, len(toTest), tt.create+len(tt.existing))

			var count int
			for _, vpsObj := range toTest {
				count++
				name := fmt.Sprintf("%s", vpsObj.Name)
				t.Run(name, func(t *testing.T) {
					// capture vpsObj for parallel test
					vpsObj := vpsObj
					t.Parallel()

					d, err := time.ParseDuration(vpsObj.Spec.TTL)
					require.NoError(t, err)

					t.Cleanup(func() {
						if !skipCleanup {
							assert.NoError(t, crdClient.Delete(ctx, vpsObj))
						}
					})
					require.NoError(t, crdClient.Create(ctx, vpsObj))

					maxTries := int(d.Seconds() * 3)
					// Wait for the operator to sync Vault PKI --> k8s Secret, and return the
					// serial number of the generated cert
					serialNumber, secret, err := waitForPKIData(t, maxTries, time.Millisecond*500,
						vpsObj, "",
					)
					require.NoError(t, err)
					assert.NotEmpty(t, serialNumber)

					assertSyncableSecret(t, crdClient, vpsObj, secret)

					if vpsObj.Spec.Destination.Create {
						expectedType := vpsObj.Spec.Destination.Type
						if expectedType == "" {
							expectedType = corev1.SecretTypeOpaque
						}
						assert.Equal(t, expectedType, secret.Type)
					}

					// Use the serial number of the first generated cert to check that the cert
					// is updated
					newSerialNumber, secret, err := waitForPKIData(t, maxTries, time.Millisecond*500,
						vpsObj, serialNumber,
					)
					require.NoError(t, err)
					assert.NotEmpty(t, newSerialNumber)

					assertSyncableSecret(t, crdClient, vpsObj, secret)

					if len(vpsObj.Spec.RolloutRestartTargets) > 0 {
						awaitRolloutRestarts(t, ctx, crdClient, vpsObj, vpsObj.Spec.RolloutRestartTargets)
					}

					if vpsObj.Spec.Destination.Create && !t.Failed() {
						if assert.NoError(t, err) {
							assertRemediationOnDestinationDeletion(t, ctx, crdClient, vpsObj,
								time.Millisecond*500, uint64(d.Seconds()*3))
						}
					}
				})
			}

			assert.Greater(t, count, 0, "no tests were run")
		})
	}
}
