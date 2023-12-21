// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
	"github.com/hashicorp/vault-secrets-operator/internal/vault"
)

func TestVaultStaticSecret(t *testing.T) {
	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testK8sNamespace2 := testK8sNamespace + "-test"
	testKvMountPath := consts.KVSecretTypeV1 + testID
	testKvv2MountPath := consts.KVSecretTypeV2 + testID
	testVaultNamespace := ""

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultstaticsecret/terraform"), tempDir)
	copyModulesDir(t, tfDir)
	chartDestDir := copyChartDir(t, tfDir)

	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}
	k8sOpts := &k8s.KubectlOptions{
		ContextName: k8sConfigContext,
		Namespace:   operatorNS,
	}
	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_test_namespace":    testK8sNamespace,
			"k8s_config_context":    k8sConfigContext,
			"vault_kv_mount_path":   testKvMountPath,
			"vault_kvv2_mount_path": testKvv2MountPath,
		},
	}
	if entTests {
		testVaultNamespace = "vault-tenant-" + testID
		tfOptions.Vars["vault_enterprise"] = true
		tfOptions.Vars["vault_test_namespace"] = testVaultNamespace
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

	kustomizeConfigPath := filepath.Join(kustomizeConfigRoot, "default")
	if !testWithHelm {
		// deploy the Operator with Kustomize
		deployOperatorWithKustomize(t, k8sOpts, kustomizeConfigPath)
	} else {
		tfOptions.Vars["deploy_operator_via_helm"] = true
		tfOptions.Vars["operator_helm_chart_path"] = chartDestDir
		if operatorImageRepo != "" {
			tfOptions.Vars["operator_image_repo"] = operatorImageRepo
		}
		if operatorImageTag != "" {
			tfOptions.Vars["operator_image_tag"] = operatorImageTag
		}
		tfOptions.Vars["enable_default_auth_method"] = true
		tfOptions.Vars["enable_default_connection"] = true
		tfOptions.Vars["k8s_vault_connection_address"] = testVaultAddress
	}

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if skipCleanup {
			t.Logf("Skipping cleanup, tfdir=%s", tfDir)
			return
		}
		for _, c := range created {
			// test that the custom resources can be deleted before tf destroy
			// removes the k8s namespace
			assert.Nil(t, crdClient.Delete(ctx, c))
		}

		exportKindLogs(t)

		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))

		// Undeploy Kustomize
		if !testWithHelm {
			k8s.KubectlDeleteFromKustomize(t, k8sOpts, kustomizeConfigPath)
		}
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, tfOptions)

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)
	// Create a VaultConnection CR
	conns := []*secretsv1beta1.VaultConnection{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultconnection-test-tenant-1",
				Namespace: testK8sNamespace2,
			},
			Spec: secretsv1beta1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}

	// Creates a default VaultConnection CR
	defaultConnection := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: operatorNS,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}

	auths := []*secretsv1beta1.VaultAuth{
		// Create a non-default VaultAuth CR
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultauth-test-tenant-1",
				Namespace: testK8sNamespace,
			},
			Spec: secretsv1beta1.VaultAuthSpec{
				// This VaultAuth references a VaultConnection in its own namespace.
				VaultConnectionRef: fmt.Sprintf("%s/vaultconnection-test-tenant-1", testK8sNamespace2),
				Namespace:          testVaultNamespace,
				Method:             "kubernetes",
				Mount:              "kubernetes",
				Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
					Role:           "role1",
					ServiceAccount: "default",
					TokenAudiences: []string{"vault"},
				},
				AllowedNamespaces: []string{"*"},
			},
		},
	}
	// Create the default VaultAuth CR in the Operator's namespace
	defaultAuthMethod := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      consts.NameDefault,
			Namespace: operatorNS,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: consts.NameDefault,
			Namespace:          testVaultNamespace,
			Method:             "kubernetes",
			Mount:              "kubernetes",
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           "role1",
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	}

	// The Helm chart will deploy the defaultAuthMethod/Connection
	if !testWithHelm {
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
	getExisting := func() []*secretsv1beta1.VaultStaticSecret {
		return []*secretsv1beta1.VaultStaticSecret{
			// Create a VaultStaticSecret CR to trigger the sync for kv
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultstaticsecret-test-kv",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					// This Secret references an Auth Method in a different namespace.
					VaultAuthRef: fmt.Sprintf("%s/%s", auths[0].ObjectMeta.Namespace, auths[0].ObjectMeta.Name),
					Namespace:    testVaultNamespace,
					Mount:        testKvMountPath,
					Type:         consts.KVSecretTypeV1,
					Path:         "secret",
					Destination: secretsv1beta1.Destination{
						Name:   "secretkv",
						Create: false,
					},
					HMACSecretData: true,
					RefreshAfter:   "5s",
					RolloutRestartTargets: []secretsv1beta1.RolloutRestartTarget{
						{
							Kind: "Deployment",
							Name: "vso",
						},
					},
				},
			},
			// Create a VaultStaticSecret CR to trigger the sync for kvv2
			{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultstaticsecret-test-kvv2",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					// This Secret references the default Auth Method.
					Namespace: testVaultNamespace,
					Mount:     testKvv2MountPath,
					Type:      consts.KVSecretTypeV2,
					Path:      "secret",
					Destination: secretsv1beta1.Destination{
						Name:   "secretkvv2",
						Create: false,
					},
					RefreshAfter:   "5s",
					HMACSecretData: false,
				},
			},
		}
	}

	// only supports string values, for the sake of simplicity
	type expectedData struct {
		initial map[string]interface{}
		update  map[string]interface{}
	}

	tests := []struct {
		name     string
		existing []*secretsv1beta1.VaultStaticSecret
		// expectedData maps to each vssObj in existing, so they need to be equal in length
		expectedExisting []expectedData
		create           int
		createTypes      []string
		version          int
	}{
		{
			name: "existing",
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
			name:        "create-kv-v1",
			create:      2,
			createTypes: []string{consts.KVSecretTypeV1},
		},
		{
			name:        "create-kv-v2",
			create:      2,
			createTypes: []string{consts.KVSecretTypeV2},
		},
		{
			name:        "create-kv-v2-fixed-version",
			create:      2,
			createTypes: []string{consts.KVSecretTypeV2},
			version:     1,
		},
		{
			name:        "create-both",
			create:      2,
			createTypes: []string{consts.KVSecretTypeV1, consts.KVSecretTypeV2},
		},
		{
			name: "mixed-both",
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
			existing:    getExisting(),
			create:      2,
			createTypes: []string{consts.KVSecretTypeV1, consts.KVSecretTypeV2},
		},
	}

	putKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret, data map[string]interface{}) {
		switch vssObj.Spec.Type {
		case consts.KVSecretTypeV1:
			require.NoError(t, vClient.KVv1(testKvMountPath).Put(ctx, vssObj.Spec.Path, data))
		case consts.KVSecretTypeV2:
			_, err := vClient.KVv2(testKvv2MountPath).Put(ctx, vssObj.Spec.Path, data)
			require.NoError(t, err)
		default:
			t.Fatalf("invalid KV type %s", vssObj.Spec.Type)
		}
	}

	deleteKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret) {
		switch vssObj.Spec.Type {
		case consts.KVSecretTypeV1:
			require.NoError(t, vClient.KVv1(testKvMountPath).Delete(ctx, vssObj.Spec.Path))
		case consts.KVSecretTypeV2:
			require.NoError(t, vClient.KVv2(testKvv2MountPath).Delete(ctx, vssObj.Spec.Path))
		default:
			t.Fatalf("invalid KV type %s", vssObj.Spec.Type)
		}
	}

	assertSync := func(t *testing.T, obj *secretsv1beta1.VaultStaticSecret, expected expectedData, expectInitial bool) {
		var data map[string]interface{}
		if expectInitial {
			putKV(t, obj, expected.initial)
			require.NoError(t, crdClient.Create(ctx, obj))
			data = expected.initial
		} else {
			putKV(t, obj, expected.update)

			if obj.Spec.Version == 1 {
				data = expected.initial
			} else {
				data = expected.update
			}
		}

		secret, err := waitForSecretData(t, ctx, crdClient, 30, 1*time.Second, obj.Spec.Destination.Name,
			obj.ObjectMeta.Namespace, data)
		if assert.NoError(t, err) {
			assertSyncableSecret(t, crdClient, obj, secret)
			if obj.Spec.HMACSecretData {
				assertHMAC(t, ctx, crdClient, obj, expectInitial)
			} else {
				assertNoHMAC(t, obj)
			}

			if obj.Spec.Destination.Create {
				sec, _, err := helpers.GetSyncableSecret(ctx, crdClient, obj)
				if assert.NoError(t, err) {
					// ensure that a Secret deleted out-of-band is properly restored
					if assert.NoError(t, crdClient.Delete(ctx, sec)) {
						_, err := waitForSecretData(t, ctx, crdClient, 30, 1*time.Second, obj.Spec.Destination.Name,
							obj.ObjectMeta.Namespace, data)
						assert.NoError(t, err)
					}
				}
			}

			if !expectInitial && len(obj.Spec.RolloutRestartTargets) > 0 {
				awaitRolloutRestarts(t, ctx, crdClient, obj, obj.Spec.RolloutRestartTargets)
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var count int
			require.Equal(t, len(tt.existing), len(tt.expectedExisting))

			for idx, vssObj := range tt.existing {
				count++
				t.Run(fmt.Sprintf("%s-existing-%d", tt.name, idx), func(t *testing.T) {
					if !skipCleanup {
						t.Cleanup(func() {
							assert.NoError(t, crdClient.Delete(ctx, vssObj))
						})
					}
					assertSync(t, vssObj, tt.expectedExisting[idx], true)
					assertSync(t, vssObj, tt.expectedExisting[idx], false)
				})
			}

			// create
			for idx := 0; idx < tt.create; idx++ {
				for _, kvType := range tt.createTypes {
					count++
					name := fmt.Sprintf("create-%s-%d", kvType, idx)
					t.Run(name, func(t *testing.T) {
						// capture idx and kvType for parallel test
						idx := idx
						kvType := kvType
						t.Parallel()

						mount := kvType + testID
						dest := fmt.Sprintf("%s-%s-%d", tt.name, kvType, idx)
						expected := expectedData{
							initial: map[string]interface{}{"dest-initial": dest},
							update:  map[string]interface{}{"dest-updated": dest},
						}
						vssObj := &secretsv1beta1.VaultStaticSecret{
							ObjectMeta: v1.ObjectMeta{
								Name:      dest,
								Namespace: testK8sNamespace,
							},
							Spec: secretsv1beta1.VaultStaticSecretSpec{
								VaultAuthRef: fmt.Sprintf("%s/%s", auths[0].ObjectMeta.Namespace, auths[0].ObjectMeta.Name),
								Namespace:    testVaultNamespace,
								Mount:        mount,
								Type:         kvType,
								Path:         dest,
								Destination: secretsv1beta1.Destination{
									Name:   dest,
									Create: true,
								},
								RefreshAfter:   "5s",
								HMACSecretData: true,
							},
						}
						if tt.version != 0 {
							vssObj.Spec.Version = tt.version
						}

						if !skipCleanup {
							t.Cleanup(func() {
								assert.NoError(t, crdClient.Delete(ctx, vssObj))
								deleteKV(t, vssObj)
							})
						}

						assertSync(t, vssObj, expected, true)
						assertSync(t, vssObj, expected, false)

						if vssObj.Spec.RefreshAfter != "" && !t.Failed() {
							d, err := time.ParseDuration(vssObj.Spec.RefreshAfter)
							if assert.NoError(t, err, "time.ParseDuration(%v)", vssObj.Spec.RefreshAfter) {
								assertRemediationOnDestinationDeletion(t, ctx, crdClient, vssObj,
									time.Millisecond*500, uint64(d.Seconds()*3))
							}
						}
					})
				}
			}

			assert.Greater(t, count, 0, "no tests were run")
		})
	}
}

func assertNoHMAC(t *testing.T, origVSSObj *secretsv1beta1.VaultStaticSecret) {
	assert.Empty(t, origVSSObj.Status.SecretMAC, "expected vssObj.Status.SecretMAC to be empty")
}

func assertHMAC(t *testing.T, ctx context.Context, client ctrlclient.Client, origVSSObj *secretsv1beta1.VaultStaticSecret,
	expectInitial bool,
) {
	t.Helper()

	if expectInitial {
		assert.Empty(t, origVSSObj.Status.SecretMAC, "expected SecretMAC to be empty on initial check")
		if t.Failed() {
			return
		}
	}

	vssObjKey := ctrlclient.ObjectKeyFromObject(origVSSObj)
	vssObj, err := awaitSecretHMACStatus(t, ctx, client, vssObjKey)
	assert.NoError(t, err)
	assert.NotNil(t, vssObj)
	if t.Failed() {
		return
	}

	if !expectInitial && origVSSObj.Status.SecretMAC == vssObj.Status.SecretMAC {
		// wait for the Status update to complete.
		assert.NoError(t, backoff.Retry(func() error {
			var v secretsv1beta1.VaultStaticSecret
			err := client.Get(ctx, vssObjKey, &v)
			if t.Failed() {
				return backoff.Permanent(err)
			}
			if v.Status.SecretMAC == origVSSObj.Status.SecretMAC {
				return fmt.Errorf("expected SecretMac to change, actual=%s", origVSSObj.Status.SecretMAC)
			}
			vssObj = &v
			return nil
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10)))
	}

	// TODO: this test is unreliable in CI. We can reenable it once we can capture
	//  the Operator logs from the Kind cluster for further analysis
	//assertSecretDataHMAC(t, ctx, client, vssObj)
	//if t.Failed() {
	//	return
	//}

	// TODO: this test is unreliable in CI. We can reenable it once we can capture
	//  the Operator logs from the Kind cluster for further analysis
	//assertHMACTriggeredRemediation(t, ctx, client, vssObj)
	//if t.Failed() {
	//	return
	//}
}

func awaitSecretHMACStatus(t *testing.T, ctx context.Context, client ctrlclient.Client,
	objKey ctrlclient.ObjectKey,
) (*secretsv1beta1.VaultStaticSecret, error) {
	t.Helper()
	var vssObj secretsv1beta1.VaultStaticSecret
	err := backoff.Retry(func() error {
		var v secretsv1beta1.VaultStaticSecret
		if err := client.Get(ctx, objKey, &v); err != nil {
			return backoff.Permanent(err)
		}

		if v.Status.SecretMAC == "" {
			return fmt.Errorf("expected Status.SecretMAC not set on %s", objKey)
		}
		vssObj = v
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))

	return &vssObj, err
}

func assertSecretDataHMAC(t *testing.T, ctx context.Context, client ctrlclient.Client, vssObj *secretsv1beta1.VaultStaticSecret,
) {
	t.Helper()

	assert.NoError(t, backoff.RetryNotify(func() error {
		obj, err := awaitSecretHMACStatus(t, ctx, client, ctrlclient.ObjectKeyFromObject(vssObj))
		if err != nil {
			return backoff.Permanent(err)
		}

		expectedMAC, err := base64.StdEncoding.DecodeString(obj.Status.SecretMAC)
		if err != nil {
			return backoff.Permanent(err)
		}

		var secret corev1.Secret
		if err := client.Get(ctx, ctrlclient.ObjectKey{Namespace: vssObj.Namespace, Name: vssObj.Spec.Destination.Name}, &secret); err != nil {
			return backoff.Permanent(err)
		}

		message, err := json.Marshal(secret.Data)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("could not marshal Secret.Data, should never happen: %w", err))
		}

		validator := helpers.NewHMACValidator(vault.DefaultClientCacheStorageConfig().HMACSecretObjKey)
		valid, actualMAC, err := validator.Validate(ctx, client, message, expectedMAC)
		if err != nil {
			return backoff.Permanent(err)
		}

		if !valid {
			return fmt.Errorf("computed message is invalid, expected %v, actual %s, data %#v",
				base64.StdEncoding.EncodeToString(expectedMAC),
				base64.StdEncoding.EncodeToString(actualMAC),
				secret.Data,
			)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 30),
		func(err error, horizon time.Duration) { log.Printf("retrying on error %q, horizon=%s", err, horizon) }),
	)
}

func assertHMACTriggeredRemediation(t *testing.T, ctx context.Context, client ctrlclient.Client,
	vssObj *secretsv1beta1.VaultStaticSecret,
) {
	t.Helper()

	var secret corev1.Secret
	secObjKey := ctrlclient.ObjectKey{Namespace: vssObj.Namespace, Name: vssObj.Spec.Destination.Name}
	assert.NoError(t, client.Get(ctx, secObjKey, &secret))
	if t.Failed() {
		return
	}

	// used for comparing map[string]interface{} to Secret.Data after mutating it below.
	origData := map[string][]byte{}
	for k, v := range secret.Data {
		origData[k] = v
	}

	// we want to test out drift detection by mutating the Secret.Data,
	// then waiting for it to be reconciled and properly remediated.
	nefariousData := map[string][]byte{
		"nefarious": []byte("actor"),
	}
	secret.Data = nefariousData
	assert.NoError(t, client.Update(ctx, &secret),
		"unexpected, could not update Secret %s", secObjKey)
	if t.Failed() {
		return
	}

	// wait for the nefarious data to be updated in the Secret
	assert.NoError(t, backoff.Retry(func() error {
		var s corev1.Secret
		if err := client.Get(ctx, secObjKey, &s); err != nil {
			return err
		}
		if !reflect.DeepEqual(nefariousData, s.Data) {
			return fmt.Errorf("nefarious data never updated in Secret %s", secObjKey)
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*250), 40)))
	if t.Failed() {
		return
	}

	// wait for the reconciler to pick up the out-of-band change
	assert.NoError(t, backoff.Retry(func() error {
		var s corev1.Secret
		if err := client.Get(ctx, secObjKey, &s); err != nil {
			return err
		}
		if !reflect.DeepEqual(origData, s.Data) {
			return fmt.Errorf("expected data %#v not restored to %s", origData, secObjKey)
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 30)))

	// assert that the vssObj.Status.SecretMAC did not change.
	vssObjKey := ctrlclient.ObjectKeyFromObject(vssObj)
	updated, err := awaitSecretHMACStatus(t, ctx, client, vssObjKey)
	assert.NoError(t, err)
	assert.NotNil(t, updated)
	if t.Failed() {
		return
	}

	assert.Equal(t, vssObj.Status.SecretMAC, updated.Status.SecretMAC)
}
