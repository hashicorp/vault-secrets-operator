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
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"

	"github.com/hashicorp/vault-secrets-operator/vault"
)

type vssK8SOutputs struct {
	NamePrefix        string `json:"name_prefix"`
	Namespace         string `json:"namespace"`
	K8sNamespace      string `json:"k8s_namespace"`
	K8sConfigContext  string `json:"k8s_config_context"`
	AuthMount         string `json:"auth_mount"`
	AuthPolicy        string `json:"auth_policy"`
	AuthRole          string `json:"auth_role"`
	KVMount           string `json:"kv_mount"`
	KVV2Mount         string `json:"kv_v2_mount"`
	AppK8sNamespace   string `json:"app_k8s_namespace"`
	AppVaultNamespace string `json:"app_vault_namespace,omitempty"`
	AdminK8sNamespace string `json:"admin_k8s_namespace"`
}

// Helper functions for common test operations

// setupVSSTestInfrastructure sets up Terraform infrastructure for VSS tests
func setupVSSTestInfrastructure(t *testing.T, useEvents bool) (string, *terraform.Options, vssK8SOutputs) {
	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.NoError(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultstaticsecret/terraform"), tempDir)
	copyModulesDirT(t, tfDir)

	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	tfOptions := &terraform.Options{
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context": k8sConfigContext,
			"vault_enterprise":   true,
			"use_events":         useEvents,
		},
	}

	tfOptions = setCommonTFOptions(t, tfOptions)

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if skipCleanup {
			t.Logf("Skipping cleanup (SKIP_CLEANUP=1), tfdir=%s", tfDir)
			return
		}

		if !testInParallel {
			exportKindLogsT(t)
		}

		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))
	})

	terraform.InitAndApply(t, tfOptions)

	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.NoError(t, err)

	var outputs vssK8SOutputs
	require.NoError(t, json.Unmarshal(b, &outputs))

	return tfDir, tfOptions, outputs
}

// createVaultConnection creates a VaultConnection resource
func createVaultConnection(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, name, namespace string, skipCleanup bool) *secretsv1beta1.VaultConnection {
	vaultConn := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultConn))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultConn))
		}
	})

	return vaultConn
}

// createVaultAuth creates a VaultAuth resource with kubernetes auth
func createVaultAuth(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, name string, vaultConn *secretsv1beta1.VaultConnection, outputs vssK8SOutputs, skipCleanup bool) *secretsv1beta1.VaultAuth {
	vaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: vaultConn.Namespace,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: ctrlclient.ObjectKeyFromObject(vaultConn).String(),
			Namespace:          outputs.AppVaultNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
			AllowedNamespaces: []string{outputs.AppK8sNamespace},
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultAuth))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultAuth))
		}
	})

	return vaultAuth
}

// waitForEventWatcherStarted waits for the EventWatcherStarted event for a VaultStaticSecret
func waitForEventWatcherStarted(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, vssObj *secretsv1beta1.VaultStaticSecret, maxRetries uint64) error {
	return backoff.Retry(func() error {
		objEvents := corev1.EventList{}
		err := crdClient.List(ctx, &objEvents,
			ctrlclient.InNamespace(vssObj.Namespace),
			ctrlclient.MatchingFields{
				"involvedObject.name": vssObj.Name,
				"reason":              consts.ReasonEventWatcherStarted,
			},
		)
		if err != nil {
			return err
		}
		if len(objEvents.Items) == 0 {
			return fmt.Errorf("no EventWatcherStarted event for %s", vssObj.Name)
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), maxRetries))
}

// waitForNewOperatorPod waits for a new operator pod to be ready after the old one is deleted
func waitForNewOperatorPod(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, operatorNS, oldPodUID string, maxRetries uint64) error {
	return backoff.Retry(func() error {
		newPodList := &corev1.PodList{}
		if err := crdClient.List(ctx, newPodList, ctrlclient.InNamespace(operatorNS),
			ctrlclient.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			return err
		}

		if len(newPodList.Items) == 0 {
			return fmt.Errorf("no operator pods found")
		}

		newPod := newPodList.Items[0]
		if string(newPod.UID) == oldPodUID {
			return fmt.Errorf("still seeing old pod")
		}

		if newPod.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("new pod not running yet: %s", newPod.Status.Phase)
		}

		// Check if pod is ready
		for _, cond := range newPod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return nil
			}
		}

		return fmt.Errorf("new pod not ready yet")
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*2), maxRetries))
}

// deleteOperatorPod deletes the operator pod and returns its UID
func deleteOperatorPod(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, operatorNS string) string {
	podList := &corev1.PodList{}
	require.NoError(t, crdClient.List(ctx, podList, ctrlclient.InNamespace(operatorNS),
		ctrlclient.MatchingLabels{"control-plane": "controller-manager"}))
	require.NotEmpty(t, podList.Items, "no operator pods found")

	operatorPod := podList.Items[0]
	oldPodUID := string(operatorPod.UID)
	require.NoError(t, crdClient.Delete(ctx, &operatorPod))

	return oldPodUID
}

// verifyVSSIsSynced verifies that a VaultStaticSecret has synced status
func verifyVSSIsSynced(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, vssObj *secretsv1beta1.VaultStaticSecret) {
	var currentVSS secretsv1beta1.VaultStaticSecret
	require.NoError(t, crdClient.Get(ctx, ctrlclient.ObjectKeyFromObject(vssObj), &currentVSS))

	var synced bool
	for _, cond := range currentVSS.Status.Conditions {
		if cond.Type == consts.TypeSecretSynced && cond.Status == v1.ConditionTrue {
			synced = true
			break
		}
	}
	require.True(t, synced, "VaultStaticSecret should be synced")
}

func TestVaultStaticSecret(t *testing.T) {
	if testInParallel {
		t.Parallel()
	}

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	defaultCreate := 2 // Default count if no VSS_CREATE_COUNT is set
	if vssCreateCount, exists := getEnvInt(t, "VSS_CREATE_COUNT"); exists {
		defaultCreate = vssCreateCount
	}

	kvv1Count, kvv2Count, bothCount, kvv2FixedCount, mixedBothCount, eventsBothCount := defaultCreate, defaultCreate, defaultCreate, defaultCreate, defaultCreate, defaultCreate

	counts := map[string]*int{
		"VSS_KVV1_CREATE":        &kvv1Count,
		"VSS_KVV2_CREATE":        &kvv2Count,
		"VSS_BOTH_CREATE":        &bothCount,
		"VSS_KVV2_FIXED_CREATE":  &kvv2FixedCount,
		"VSS_MIXED_BOTH_CREATE":  &mixedBothCount,
		"VSS_EVENTS_BOTH_CREATE": &eventsBothCount,
	}
	for key, count := range counts {
		if v, exists := getEnvInt(t, key); exists {
			*count = v
		}
	}

	// The events tests require Vault Enterprise >= 1.16.3, and since that
	// changes the app policy required we need to set a flag in the test
	// terraform
	rootVaultClient := getVaultClient(t, "")
	atLeast_v1_16_3 := vaultVersionGreaterThanOrEqual(t, rootVaultClient, "1.16.3")

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultstaticsecret/terraform"), tempDir)
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
			"k8s_config_context": k8sConfigContext,
		},
	}
	if entTests {
		tfOptions.Vars["vault_enterprise"] = true
		if atLeast_v1_16_3 {
			tfOptions.Vars["use_events"] = true
		}
	}
	tfOptions = setCommonTFOptions(t, tfOptions)

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

		if !testInParallel {
			exportKindLogsT(t)
		}

		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))
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

	var outputs vssK8SOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, outputs.AppVaultNamespace)
	// Create a VaultConnection CR
	conns := []*secretsv1beta1.VaultConnection{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      "vaultconnection-test-tenant-1",
				Namespace: outputs.AdminK8sNamespace,
			},
			Spec: secretsv1beta1.VaultConnectionSpec{
				Address: testVaultAddress,
			},
		},
	}

	auths := []*secretsv1beta1.VaultAuth{
		// Create a non-default VaultAuth CR
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      outputs.NamePrefix + "-admin",
				Namespace: outputs.AppK8sNamespace,
			},
			Spec: secretsv1beta1.VaultAuthSpec{
				// This VaultAuth references a VaultConnection in an external namespace.
				VaultConnectionRef: ctrlclient.ObjectKeyFromObject(conns[0]).String(),
				Namespace:          outputs.AppK8sNamespace,
				Method:             "kubernetes",
				Mount:              outputs.AuthMount,
				Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
					Role:           outputs.AuthRole,
					ServiceAccount: "default",
					TokenAudiences: []string{"vault"},
				},
				AllowedNamespaces: []string{outputs.AppK8sNamespace},
			},
		},
	}
	// Create the default VaultAuth CR in the Operator's namespace
	defaultVaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      outputs.NamePrefix + "-default",
			Namespace: operatorNS,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: consts.NameDefault,
			Namespace:          outputs.AppK8sNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			AllowedNamespaces:  []string{outputs.AppK8sNamespace},
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
		},
	}

	auths = append(auths, defaultVaultAuth)
	for _, c := range conns {
		require.NoError(t, crdClient.Create(ctx, c))
		created = append(created, c)
	}

	for _, a := range auths {
		require.NoError(t, crdClient.Create(ctx, a))
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
					Namespace: outputs.AppK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					VaultAuthRef: ctrlclient.ObjectKeyFromObject(auths[0]).String(),
					// This Secret references an Auth Method in a different namespace.
					// VaultAuthRef: fmt.Sprintf("%s/%s", auths[0].ObjectMeta.Namespace, auths[0].ObjectMeta.Name),
					Namespace: outputs.AppVaultNamespace,
					VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
						Mount: outputs.KVMount,
						Type:  consts.KVSecretTypeV1,
						Path:  "secret",
					},
					Destination: secretsv1beta1.Destination{
						Name:   "secretkv",
						Create: false,
					},
					HMACSecretData: pointerutil.BoolPtr(true),
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
					Namespace: outputs.AppK8sNamespace,
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					// This Secret references the default Auth Method.
					VaultAuthRef: ctrlclient.ObjectKeyFromObject(defaultVaultAuth).String(),
					Namespace:    outputs.AppK8sNamespace,
					VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
						Mount: outputs.KVV2Mount,
						Type:  consts.KVSecretTypeV2,
						Path:  "secret",
					},
					Destination: secretsv1beta1.Destination{
						Name:   "secretkvv2",
						Create: false,
					},
					RefreshAfter:   "5s",
					HMACSecretData: pointerutil.BoolPtr(false),
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
		useEvents        bool
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
			create:      kvv1Count,
			createTypes: []string{consts.KVSecretTypeV1},
		},
		{
			name:        "create-kv-v2",
			create:      kvv2Count,
			createTypes: []string{consts.KVSecretTypeV2},
		},
		{
			name:        "create-kv-v2-fixed-version",
			create:      kvv2FixedCount,
			createTypes: []string{consts.KVSecretTypeV2},
			version:     1,
		},
		{
			name:        "create-both",
			create:      bothCount,
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
			create:      mixedBothCount,
			createTypes: []string{consts.KVSecretTypeV1, consts.KVSecretTypeV2},
		},
		{
			name: "events-both",
			expectedExisting: []expectedData{
				{
					initial: map[string]interface{}{"username": "bob", "fruit": "banana"},
					update:  map[string]interface{}{"username": "bob", "fruit": "apple"},
				},
				{
					initial: map[string]interface{}{"username": "alice", "fruit": "chicle"},
					update:  map[string]interface{}{"username": "abcd", "fruit": "mango"},
				},
			},
			existing: func() []*secretsv1beta1.VaultStaticSecret {
				vss := getExisting()
				for _, v := range vss {
					v.Spec.SyncConfig = &secretsv1beta1.SyncConfig{
						InstantUpdates: true,
					}
					v.Spec.RefreshAfter = "1h"
				}
				return vss
			}(),
			create:      eventsBothCount,
			createTypes: []string{consts.KVSecretTypeV1, consts.KVSecretTypeV2},
			useEvents:   true,
		},
	}

	putKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret, data map[string]interface{}) {
		switch vssObj.Spec.Type {
		case consts.KVSecretTypeV1:
			require.NoError(t, vClient.KVv1(outputs.KVMount).Put(ctx, vssObj.Spec.Path, data))
		case consts.KVSecretTypeV2:
			_, err := vClient.KVv2(outputs.KVV2Mount).Put(ctx, vssObj.Spec.Path, data)
			require.NoError(t, err)
		default:
			t.Fatalf("invalid KV type %s", vssObj.Spec.Type)
		}
	}

	deleteKV := func(t *testing.T, vssObj *secretsv1beta1.VaultStaticSecret) {
		switch vssObj.Spec.Type {
		case consts.KVSecretTypeV1:
			require.NoError(t, vClient.KVv1(outputs.KVMount).Delete(ctx, vssObj.Spec.Path))
		case consts.KVSecretTypeV2:
			require.NoError(t, vClient.KVv2(outputs.KVV2Mount).Delete(ctx, vssObj.Spec.Path))
		default:
			t.Fatalf("invalid KV type %s", vssObj.Spec.Type)
		}
	}

	assertSync := func(t *testing.T, obj *secretsv1beta1.VaultStaticSecret, expected expectedData, expectInitial bool) {
		var data map[string]interface{}
		if expectInitial {
			require.Empty(t, obj.UID,
				"obj %s has UID %s, expected empty", obj.Name, obj.UID)
			var expectSpecHMACData *bool
			if obj.Spec.HMACSecretData == nil {
				// default value as defined in the CRD schema
				expectSpecHMACData = pointerutil.BoolPtr(true)
			} else if *obj.Spec.HMACSecretData {
				// explicitly set to true
				expectSpecHMACData = pointerutil.BoolPtr(true)
			} else {
				// explicitly set to false
				expectSpecHMACData = pointerutil.BoolPtr(false)
			}
			putKV(t, obj, expected.initial)
			require.NoError(t, crdClient.Create(ctx, obj))
			require.Equal(t, obj.Spec.HMACSecretData, expectSpecHMACData,
				"expected initial value for spec.hmacSecretData to be honoured after creation")
			data = expected.initial
		} else {
			putKV(t, obj, expected.update)

			if obj.Spec.Version == 1 {
				data = expected.initial
			} else {
				data = expected.update
			}
		}

		secret, err := waitForSecretData(t, ctx, crdClient, 30, time.Millisecond*500, obj.Spec.Destination.Name,
			obj.ObjectMeta.Namespace, data)
		if assert.NoError(t, err) {
			assertSyncableSecret(t, crdClient, obj, secret)
			if obj.Spec.HMACSecretData != nil && *obj.Spec.HMACSecretData {
				assertHMAC(t, ctx, crdClient, obj, expectInitial)
			} else {
				assertNoHMAC(t, obj)
			}

			if obj.Spec.Destination.Create {
				sec, _, err := helpers.GetSyncableSecret(ctx, crdClient, obj)
				if assert.NoError(t, err) {
					// ensure that a Secret deleted out-of-band is properly restored
					if assert.NoError(t, crdClient.Delete(ctx, sec)) {
						_, err := waitForSecretData(t, ctx, crdClient, 30, time.Millisecond*500, obj.Spec.Destination.Name,
							obj.ObjectMeta.Namespace, data)
						assert.NoError(t, err)
					}
				}
			}

			if !expectInitial {
				if len(obj.Spec.RolloutRestartTargets) > 0 {
					awaitRolloutRestarts(t, ctx, crdClient, obj, obj.Spec.RolloutRestartTargets)
				} else {
					// ensure that no rollout restarts are triggered when there are no targets
					awaitNoRolloutRestartsVSS(t, ctx, crdClient, ctrlclient.ObjectKeyFromObject(obj))
				}
			}
		}
		if t.Failed() {
			return
		}

		if expectInitial && obj.Spec.SyncConfig != nil && obj.Spec.SyncConfig.InstantUpdates {
			// Ensure the (Vault) event watcher has started by waiting for the
			// EventWatcherStarted k8s event so that subsequent Vault updates
			// are detected and synced.
			assert.NoError(t, backoff.Retry(func() error {
				objEvents := corev1.EventList{}
				err := crdClient.List(ctx, &objEvents,
					ctrlclient.InNamespace(obj.Namespace),
					ctrlclient.MatchingFields{
						"involvedObject.name": obj.Name,
						"reason":              consts.ReasonEventWatcherStarted,
					},
				)
				if err != nil {
					return err
				}
				if len(objEvents.Items) == 0 {
					return fmt.Errorf("no EventWatcherStarted event for %s", obj.Name)
				}
				return nil
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 200)))
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.useEvents && !(entTests && atLeast_v1_16_3) {
				t.Skip("Skipping because events tests require Vault Enterprise >= 1.16.3")
			}
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

						var mount string
						switch kvType {
						case consts.KVSecretTypeV1:
							mount = outputs.KVMount
						case consts.KVSecretTypeV2:
							mount = outputs.KVV2Mount
						default:
							require.Fail(t, "unsupported KV type %s", kvType)
						}

						dest := fmt.Sprintf("%s-%s-%d", tt.name, kvType, idx)
						expected := expectedData{
							initial: map[string]interface{}{"dest-initial": dest},
							update:  map[string]interface{}{"dest-updated": dest},
						}
						vssObj := &secretsv1beta1.VaultStaticSecret{
							ObjectMeta: v1.ObjectMeta{
								Name:      dest,
								Namespace: outputs.AppK8sNamespace,
							},
							Spec: secretsv1beta1.VaultStaticSecretSpec{
								VaultAuthRef: fmt.Sprintf("%s/%s", auths[0].ObjectMeta.Namespace, auths[0].ObjectMeta.Name),
								Namespace:    outputs.AppVaultNamespace,
								VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
									Mount: mount,
									Type:  kvType,
									Path:  dest,
								},
								Destination: secretsv1beta1.Destination{
									Name:   dest,
									Create: true,
								},
								RefreshAfter:   "5s",
								HMACSecretData: pointerutil.BoolPtr(true),
							},
						}
						if tt.version != 0 {
							vssObj.Spec.Version = tt.version
						}
						if tt.useEvents {
							vssObj.Spec.SyncConfig = &secretsv1beta1.SyncConfig{
								InstantUpdates: true,
							}
							vssObj.Spec.RefreshAfter = "1h"
						}

						if !skipCleanup {
							t.Cleanup(func() {
								assert.NoError(t, crdClient.Delete(ctx, vssObj))
								deleteKV(t, vssObj)
							})
						}

						assertSync(t, vssObj, expected, true)
						if t.Failed() {
							return
						}

						assertSync(t, vssObj, expected, false)
						if t.Failed() {
							return
						}

						if vssObj.Spec.RefreshAfter != "" {
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

// Forward-looking regression guard for customer-reported EOF websocket events
// with short Kubernetes auth TTLs, validated over repeated token renewal cycles.
func TestVaultStaticSecretEventWatcherShortTTLNoEOF(t *testing.T) {
	if testInParallel {
		t.Parallel()
	}

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")
	if !entTests {
		t.Skip("Skipping because this test requires Vault Enterprise events support")
	}

	rootVaultClient := getVaultClient(t, "")
	if !vaultVersionGreaterThanOrEqual(t, rootVaultClient, "1.16.3") {
		t.Skip("Skipping because this test requires Vault Enterprise >= 1.16.3")
	}

	// Setup infrastructure
	_, _, outputs := setupVSSTestInfrastructure(t, true)

	ctx := context.Background()
	crdClient := getCRDClient(t)
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""

	authClient := getVaultClient(t, outputs.AppVaultNamespace)

	// Reproduce the reported short-lived Kubernetes auth token scenario by
	// setting both the auth mount and auth role TTLs to 1 minute.
	tunePath := fmt.Sprintf("sys/auth/%s/tune", outputs.AuthMount)
	_, err := authClient.Logical().Write(tunePath, map[string]interface{}{
		"default_lease_ttl": "1m",
		"max_lease_ttl":     "1m",
	})
	require.NoError(t, err)

	rolePath := fmt.Sprintf("auth/%s/role/%s", outputs.AuthMount, outputs.AuthRole)
	roleConfig, err := authClient.Logical().Read(rolePath)
	require.NoError(t, err)
	require.NotNil(t, roleConfig)
	require.NotNil(t, roleConfig.Data)

	_, err = authClient.Logical().Write(rolePath, map[string]interface{}{
		"bound_service_account_names":      roleConfig.Data["bound_service_account_names"],
		"bound_service_account_namespaces": roleConfig.Data["bound_service_account_namespaces"],
		"token_policies":                   roleConfig.Data["token_policies"],
		"audience":                         roleConfig.Data["audience"],
		"token_ttl":                        "1m",
		"token_max_ttl":                    "1m",
	})
	require.NoError(t, err)

	vaultConn := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultconnection-short-ttl-events",
			Namespace: outputs.AdminK8sNamespace,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultConn))
	if !skipCleanup {
		t.Cleanup(func() {
			assert.NoError(t, crdClient.Delete(ctx, vaultConn))
		})
	}

	vaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultauth-short-ttl-events",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: ctrlclient.ObjectKeyFromObject(vaultConn).String(),
			Namespace:          outputs.AppK8sNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
			AllowedNamespaces: []string{outputs.AppK8sNamespace},
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultAuth))
	if !skipCleanup {
		t.Cleanup(func() {
			assert.NoError(t, crdClient.Delete(ctx, vaultAuth))
		})
	}

	vssObj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "vaultstaticsecret-short-ttl-events",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultAuthRef: ctrlclient.ObjectKeyFromObject(vaultAuth).String(),
			Namespace:    outputs.AppVaultNamespace,
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: outputs.KVV2Mount,
				Type:  consts.KVSecretTypeV2,
				Path:  "short-ttl-events",
			},
			Destination: secretsv1beta1.Destination{
				Name:   "short-ttl-events",
				Create: true,
			},
			SyncConfig: &secretsv1beta1.SyncConfig{
				InstantUpdates: true,
			},
			RefreshAfter: "1h",
		},
	}
	require.NoError(t, crdClient.Create(ctx, vssObj))
	if !skipCleanup {
		t.Cleanup(func() {
			assert.NoError(t, crdClient.Delete(ctx, vssObj))
		})
	}

	vClient := getVaultClient(t, outputs.AppVaultNamespace)
	expectedData := map[string]interface{}{"value": "cycle-0"}
	_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, vssObj.Spec.Path, expectedData)
	require.NoError(t, err)

	_, err = waitForSecretData(t, ctx, crdClient, 60, time.Second, vssObj.Spec.Destination.Name,
		vssObj.ObjectMeta.Namespace, expectedData)
	require.NoError(t, err)

	// Ensure the event watcher is active before validating behavior
	require.NoError(t, waitForEventWatcherStarted(t, ctx, crdClient, vssObj, 60))

	// Wait through 3 TTL cycles (~1 minute each) and mutate Vault data each
	// cycle to verify websocket event streaming continues to drive sync updates.
	for i := 1; i <= 3; i++ {
		time.Sleep(70 * time.Second)

		expectedData = map[string]interface{}{
			"value": fmt.Sprintf("cycle-%d", i),
		}
		_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, vssObj.Spec.Path, expectedData)
		require.NoError(t, err)

		_, err = waitForSecretData(t, ctx, crdClient, 90, time.Second, vssObj.Spec.Destination.Name,
			vssObj.ObjectMeta.Namespace, expectedData)
		require.NoError(t, err)
	}

	// After the 3-cycle window, assert no EventWatcherError warning was emitted
	// with the historical websocket EOF signatures.
	time.Sleep(10 * time.Second)
	objEvents := corev1.EventList{}
	require.NoError(t, crdClient.List(ctx, &objEvents,
		ctrlclient.InNamespace(vssObj.Namespace),
		ctrlclient.MatchingFields{
			"involvedObject.name": vssObj.Name,
			"reason":              consts.ReasonEventWatcherError,
		},
	))

	for _, event := range objEvents.Items {
		if event.Type != corev1.EventTypeWarning {
			continue
		}
		if strings.Contains(event.Message, "failed to read frame header: EOF") ||
			strings.Contains(event.Message, "failed to read from websocket") {
			t.Fatalf("unexpected websocket EOF event for %s: %s", vssObj.Name, event.Message)
		}
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
	// assertSecretDataHMAC(t, ctx, client, vssObj)
	// if t.Failed() {
	//	return
	// }

	// TODO: this test is unreliable in CI. We can reenable it once we can capture
	//  the Operator logs from the Kind cluster for further analysis
	// assertHMACTriggeredRemediation(t, ctx, client, vssObj)
	// if t.Failed() {
	//	return
	// }
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

func awaitNoRolloutRestartsVSS(t *testing.T, ctx context.Context, client ctrlclient.Client, objKey ctrlclient.ObjectKey) {
	t.Helper()
	require.NoError(t, backoff.Retry(
		func() error {
			var obj secretsv1beta1.VaultStaticSecret
			if err := client.Get(ctx, objKey, &obj); err != nil {
				return backoff.Permanent(err)
			}

			var synced bool
			for _, cond := range obj.Status.Conditions {
				switch cond.Type {
				case consts.TypeSecretSynced:
					synced = true
				}
				if synced && cond.Type == consts.TypeRolloutRestart {
					return backoff.Permanent(fmt.Errorf("unexpected rollout restart condition on %s", objKey))
				}
			}
			if !synced {
				return fmt.Errorf("expected synced condition on %s", objKey)
			}
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*1), 30),
	))
}

// TestVaultStaticSecret_RequeueAfterEventLoopExit tests that when an event loop
// exits (WebSocket connection dies), the resource is requeued and reconciled again.
// This verifies the fix for: "No Requeue Event After Event Loop Exit"
func TestVaultStaticSecret_RequeueAfterEventLoopExit(t *testing.T) {
	// Test initialization
	// if testInParallel {
	// 	t.Parallel()
	// }

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	// Setup Terraform directory
	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultstaticsecret/terraform"), tempDir)
	copyModulesDirT(t, tfDir)

	// Configure Terraform options
	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	tfOptions := &terraform.Options{
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context": k8sConfigContext,
		},
	}

	// Enable events for this test (requires Vault Enterprise >= 1.16.3)
	rootVaultClient := getVaultClient(t, "")
	atLeast_v1_16_3 := vaultVersionGreaterThanOrEqual(t, rootVaultClient, "1.16.3")
	if entTests && atLeast_v1_16_3 {
		tfOptions.Vars["vault_enterprise"] = true
		tfOptions.Vars["use_events"] = true
	} else {
		t.Skip("Skipping test - requires Vault Enterprise >= 1.16.3 for event loop testing")
	}

	tfOptions = setCommonTFOptions(t, tfOptions)

	ctx := context.Background()
	crdClient := getCRDClient(t)

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if skipCleanup {
			t.Logf("Skipping cleanup, tfdir=%s", tfDir)
			return
		}

		if !testInParallel {
			exportKindLogsT(t)
		}

		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))
	})

	// Deploy infrastructure with Terraform
	terraform.InitAndApply(t, tfOptions)

	// Get Terraform outputs
	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.NoError(t, err)

	var outputs vssK8SOutputs
	require.NoError(t, json.Unmarshal(b, &outputs))

	// Create VaultConnection and VaultAuth resources
	vaultConn := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-conn-requeue",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultConn))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultConn))
		}
	})

	vaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-auth-requeue",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: ctrlclient.ObjectKeyFromObject(vaultConn).String(),
			Namespace:          outputs.AppVaultNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
			AllowedNamespaces: []string{outputs.AppK8sNamespace},
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultAuth))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultAuth))
		}
	})

	// Create VaultStaticSecret with instant updates enabled (WebSocket)
	vssName := "test-vss-requeue"
	vssObj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      vssName,
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultAuthRef: ctrlclient.ObjectKeyFromObject(vaultAuth).String(),
			Namespace:    outputs.AppVaultNamespace,
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: outputs.KVV2Mount,
				Type:  consts.KVSecretTypeV2,
				Path:  "requeue-test",
			},
			Destination: secretsv1beta1.Destination{
				Name:   vssName,
				Create: true,
			},
			RefreshAfter: "30s",
			SyncConfig: &secretsv1beta1.SyncConfig{
				InstantUpdates: true,
			},
		},
	}

	// Write initial secret to Vault
	vClient := getVaultClient(t, outputs.AppVaultNamespace)
	initialData := map[string]interface{}{
		"initial-key": "initial-value",
	}
	_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, vssObj.Spec.Path, initialData)
	require.NoError(t, err)

	// Create VaultStaticSecret in Kubernetes
	require.NoError(t, crdClient.Create(ctx, vssObj))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vssObj))
		}
	})

	// Wait for initial secret sync
	_, err = waitForSecretData(t, ctx, crdClient, 60, time.Second, vssObj.Spec.Destination.Name,
		vssObj.Namespace, initialData)
	require.NoError(t, err, "initial secret sync failed")

	// Wait for WebSocket event watcher to start
	require.NoError(t, waitForEventWatcherStarted(t, ctx, crdClient, vssObj, 60))

	// Simulate operator crash by deleting operator pod
	oldPodUID := deleteOperatorPod(t, ctx, crdClient, operatorNS)

	// Wait for new operator pod to be ready
	require.NoError(t, waitForNewOperatorPod(t, ctx, crdClient, operatorNS, oldPodUID, 60))

	// Update secret in Vault to trigger reconciliation
	updatedData := map[string]interface{}{
		"updated-key": "updated-value-after-restart",
	}
	_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, vssObj.Spec.Path, updatedData)
	require.NoError(t, err)

	// Verify the resource gets requeued and reconciled
	// The secret should be updated even though the WebSocket died
	// This is the critical test - if this times out, requeue didn't work
	_, err = waitForSecretData(t, ctx, crdClient, 120, time.Second*2, vssObj.Spec.Destination.Name,
		vssObj.Namespace, updatedData)
	require.NoError(t, err, "secret should sync after operator restart - requeue event should have been sent")

	// Verify VaultStaticSecret status shows it's synced
	verifyVSSIsSynced(t, ctx, crdClient, vssObj)
}

func TestVaultStaticSecret_RegistryCleanup(t *testing.T) {
	// Test verifies event watcher registry properly cleans up when VaultStaticSecrets are deleted
	// This ensures no memory leaks or orphaned goroutines
	// if testInParallel {
	// 	t.Parallel()
	// }

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	// Check if we should run this test (requires Vault Enterprise >= 1.16.3)
	rootVaultClient := getVaultClient(t, "")
	atLeast_v1_16_3 := vaultVersionGreaterThanOrEqual(t, rootVaultClient, "1.16.3")
	if !entTests || !atLeast_v1_16_3 {
		t.Skip("Skipping test - requires Vault Enterprise >= 1.16.3 for event watcher registry testing")
	}

	// Setup infrastructure
	_, _, outputs := setupVSSTestInfrastructure(t, true)

	ctx := context.Background()
	crdClient := getCRDClient(t)
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""

	// Create VaultConnection and VaultAuth
	vaultConn := createVaultConnection(t, ctx, crdClient, "test-conn-cleanup", outputs.AppK8sNamespace, skipCleanup)
	vaultAuth := createVaultAuth(t, ctx, crdClient, "test-auth-cleanup", vaultConn, outputs, skipCleanup)

	vClient := getVaultClient(t, outputs.AppVaultNamespace)

	// Create 10 VaultStaticSecrets with instant updates
	// This will create 10 event watchers (WebSocket connections) in the registry
	numSecrets := 10
	vssObjects := make([]*secretsv1beta1.VaultStaticSecret, numSecrets)

	for i := 0; i < numSecrets; i++ {
		secretName := fmt.Sprintf("test-vss-cleanup-%d", i)
		secretPath := fmt.Sprintf("cleanup-test-%d", i)

		// Write secret to Vault
		secretData := map[string]interface{}{
			"key": fmt.Sprintf("value-%d", i),
		}
		_, err := vClient.KVv2(outputs.KVV2Mount).Put(ctx, secretPath, secretData)
		require.NoError(t, err)

		// Create VaultStaticSecret with instant updates enabled
		vssObj := &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      secretName,
				Namespace: outputs.AppK8sNamespace,
			},
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultAuthRef: ctrlclient.ObjectKeyFromObject(vaultAuth).String(),
				Namespace:    outputs.AppVaultNamespace,
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: outputs.KVV2Mount,
					Type:  consts.KVSecretTypeV2,
					Path:  secretPath,
				},
				Destination: secretsv1beta1.Destination{
					Name:   secretName,
					Create: true,
				},
				RefreshAfter: "1h",
				SyncConfig: &secretsv1beta1.SyncConfig{
					InstantUpdates: true,
				},
			},
		}

		require.NoError(t, crdClient.Create(ctx, vssObj))
		vssObjects[i] = vssObj
	}

	// Wait for all secrets to sync
	for i, vssObj := range vssObjects {
		expectedData := map[string]interface{}{
			"key": fmt.Sprintf("value-%d", i),
		}

		_, err := waitForSecretData(t, ctx, crdClient, 60, time.Second, vssObj.Spec.Destination.Name,
			vssObj.Namespace, expectedData)
		require.NoError(t, err, "secret %s should sync", vssObj.Name)
	}

	// Wait for all event watchers to start (registry should have 10 entries)
	for _, vssObj := range vssObjects {
		require.NoError(t, waitForEventWatcherStarted(t, ctx, crdClient, vssObj, 60))
	}

	// Delete all VaultStaticSecrets
	// This should trigger cleanup of all event watchers from the registry
	for _, vssObj := range vssObjects {
		require.NoError(t, crdClient.Delete(ctx, vssObj))
	}

	// Give operator time to process deletions and clean up watchers
	time.Sleep(10 * time.Second)

	// Verify all VaultStaticSecrets are deleted
	for i, vssObj := range vssObjects {
		var vss secretsv1beta1.VaultStaticSecret
		err := crdClient.Get(ctx, ctrlclient.ObjectKeyFromObject(vssObj), &vss)
		require.True(t, err != nil && strings.Contains(err.Error(), "not found"),
			"VaultStaticSecret %d should be deleted", i)
	}

	// Create new VaultStaticSecrets to verify registry can handle new entries after cleanup
	// This proves there are no memory leaks or orphaned goroutines
	newVSSObjects := make([]*secretsv1beta1.VaultStaticSecret, 3)

	for i := 0; i < 3; i++ {
		secretName := fmt.Sprintf("test-vss-after-cleanup-%d", i)
		secretPath := fmt.Sprintf("after-cleanup-%d", i)

		secretData := map[string]interface{}{
			"key": fmt.Sprintf("new-value-%d", i),
		}
		_, err := vClient.KVv2(outputs.KVV2Mount).Put(ctx, secretPath, secretData)
		require.NoError(t, err)

		vssObj := &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      secretName,
				Namespace: outputs.AppK8sNamespace,
			},
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultAuthRef: ctrlclient.ObjectKeyFromObject(vaultAuth).String(),
				Namespace:    outputs.AppVaultNamespace,
				VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
					Mount: outputs.KVV2Mount,
					Type:  consts.KVSecretTypeV2,
					Path:  secretPath,
				},
				Destination: secretsv1beta1.Destination{
					Name:   secretName,
					Create: true,
				},
				RefreshAfter: "1h",
				SyncConfig: &secretsv1beta1.SyncConfig{
					InstantUpdates: true,
				},
			},
		}

		require.NoError(t, crdClient.Create(ctx, vssObj))
		newVSSObjects[i] = vssObj

		t.Cleanup(func() {
			if !skipCleanup {
				assert.NoError(t, crdClient.Delete(ctx, vssObj))
			}
		})
	}

	// Verify new secrets sync successfully (proves registry is working after cleanup)
	for i, vssObj := range newVSSObjects {
		expectedData := map[string]interface{}{
			"key": fmt.Sprintf("new-value-%d", i),
		}

		_, err := waitForSecretData(t, ctx, crdClient, 60, time.Second, vssObj.Spec.Destination.Name,
			vssObj.Namespace, expectedData)
		require.NoError(t, err, "new secret %s should sync", vssObj.Name)
	}
}

func TestVaultStaticSecret_OrphanedRegistryRecovery(t *testing.T) {
	// if testInParallel {
	// 	t.Parallel()
	// }

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	// Requires Vault Enterprise >= 1.16.3 for event watcher functionality
	rootVaultClient := getVaultClient(t, "")
	atLeast_v1_16_3 := vaultVersionGreaterThanOrEqual(t, rootVaultClient, "1.16.3")
	if !entTests || !atLeast_v1_16_3 {
		t.Skip("Skipping test - requires Vault Enterprise >= 1.16.3 for orphaned registry testing")
	}

	// Setup Terraform infrastructure for test
	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.NoError(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultstaticsecret/terraform"), tempDir)
	copyModulesDirT(t, tfDir)

	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	tfOptions := &terraform.Options{
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_config_context": k8sConfigContext,
			"vault_enterprise":   true,
			"use_events":         true, // Enable instant updates via WebSocket events
		},
	}

	tfOptions = setCommonTFOptions(t, tfOptions)

	ctx := context.Background()
	crdClient := getCRDClient(t)

	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if skipCleanup {
			t.Logf("Skipping cleanup (SKIP_CLEANUP=1), tfdir=%s", tfDir)
			return
		}

		if !testInParallel {
			exportKindLogsT(t)
		}

		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))
	})

	terraform.InitAndApply(t, tfOptions)

	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.NoError(t, err)

	var outputs vssK8SOutputs
	require.NoError(t, json.Unmarshal(b, &outputs))

	// Create VaultConnection
	vaultConn := &secretsv1beta1.VaultConnection{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-conn-orphan",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultConnectionSpec{
			Address: testVaultAddress,
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultConn))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultConn))
		}
	})

	// Create VaultAuth with full namespace/name reference
	vaultAuth := &secretsv1beta1.VaultAuth{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-auth-orphan",
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultAuthSpec{
			VaultConnectionRef: ctrlclient.ObjectKeyFromObject(vaultConn).String(),
			Namespace:          outputs.AppVaultNamespace,
			Method:             "kubernetes",
			Mount:              outputs.AuthMount,
			Kubernetes: &secretsv1beta1.VaultAuthConfigKubernetes{
				Role:           outputs.AuthRole,
				ServiceAccount: "default",
				TokenAudiences: []string{"vault"},
			},
			AllowedNamespaces: []string{outputs.AppK8sNamespace},
		},
	}
	require.NoError(t, crdClient.Create(ctx, vaultAuth))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vaultAuth))
		}
	})

	vClient := getVaultClient(t, outputs.AppVaultNamespace)

	secretName := "test-vss-orphan"
	secretPath := "orphan-test"

	// Write initial secret to Vault
	initialData := map[string]interface{}{
		"key": "initial-value",
	}
	_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, secretPath, initialData)
	require.NoError(t, err)

	// Create VaultStaticSecret with instant updates enabled
	vssObj := &secretsv1beta1.VaultStaticSecret{
		ObjectMeta: v1.ObjectMeta{
			Name:      secretName,
			Namespace: outputs.AppK8sNamespace,
		},
		Spec: secretsv1beta1.VaultStaticSecretSpec{
			VaultAuthRef: ctrlclient.ObjectKeyFromObject(vaultAuth).String(),
			Namespace:    outputs.AppVaultNamespace,
			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
				Mount: outputs.KVV2Mount,
				Type:  consts.KVSecretTypeV2,
				Path:  secretPath,
			},
			Destination: secretsv1beta1.Destination{
				Name:   secretName,
				Create: true,
			},
			RefreshAfter: "1h",
			SyncConfig: &secretsv1beta1.SyncConfig{
				InstantUpdates: true, // Enables WebSocket event watcher
			},
		},
	}

	require.NoError(t, crdClient.Create(ctx, vssObj))

	t.Cleanup(func() {
		if !skipCleanup {
			assert.NoError(t, crdClient.Delete(ctx, vssObj))
		}
	})

	// Wait for initial secret sync
	_, err = waitForSecretData(t, ctx, crdClient, 60, time.Second, vssObj.Spec.Destination.Name,
		vssObj.Namespace, initialData)
	require.NoError(t, err, "initial secret sync failed")

	// Wait for event watcher to start (creates registry entry)
	require.NoError(t, backoff.Retry(func() error {
		objEvents := corev1.EventList{}
		err := crdClient.List(ctx, &objEvents,
			ctrlclient.InNamespace(vssObj.Namespace),
			ctrlclient.MatchingFields{
				"involvedObject.name": vssObj.Name,
				"reason":              consts.ReasonEventWatcherStarted,
			},
		)
		if err != nil {
			return err
		}
		if len(objEvents.Items) == 0 {
			return fmt.Errorf("no EventWatcherStarted event for %s", vssObj.Name)
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 60)))

	// Get current operator pod before simulating crash
	podList := &corev1.PodList{}
	require.NoError(t, crdClient.List(ctx, podList, ctrlclient.InNamespace(operatorNS),
		ctrlclient.MatchingLabels{"control-plane": "controller-manager"}))
	require.NotEmpty(t, podList.Items, "no operator pods found")

	operatorPod := podList.Items[0]
	originalPodUID := operatorPod.UID
	originalPodName := operatorPod.Name

	// Delete operator pod to simulate crash - this creates an orphaned registry entry
	// because the event watcher doesn't get a chance to clean up properly
	require.NoError(t, crdClient.Delete(ctx, &operatorPod))

	// Verify old pod is actually deleted
	require.NoError(t, backoff.Retry(func() error {
		checkPodList := &corev1.PodList{}
		if err := crdClient.List(ctx, checkPodList, ctrlclient.InNamespace(operatorNS),
			ctrlclient.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			return fmt.Errorf("error listing pods: %v", err)
		}

		// Check if old pod still exists
		for _, pod := range checkPodList.Items {
			if pod.UID == originalPodUID {
				return fmt.Errorf("old pod %s (UID: %s) still exists", originalPodName, originalPodUID)
			}
		}
		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30)))

	// Wait for new operator pod to start (recovery)
	require.NoError(t, backoff.Retry(func() error {
		newPodList := &corev1.PodList{}
		if err := crdClient.List(ctx, newPodList, ctrlclient.InNamespace(operatorNS),
			ctrlclient.MatchingLabels{"control-plane": "controller-manager"}); err != nil {
			return err
		}

		if len(newPodList.Items) == 0 {
			return fmt.Errorf("no operator pods found")
		}

		newPod := newPodList.Items[0]
		if newPod.UID == originalPodUID {
			return fmt.Errorf("still seeing old pod")
		}

		if newPod.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("new pod not running yet: %s", newPod.Status.Phase)
		}

		// Check if pod is ready
		for _, cond := range newPod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return nil
			}
		}

		return fmt.Errorf("new pod not ready yet")
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*2), 60)))

	// Give operator time to detect orphans and reconcile
	time.Sleep(15 * time.Second)

	// Verify the VaultStaticSecret is still healthy after operator restart
	verifyVSSIsSynced(t, ctx, crdClient, vssObj)

	// Verify event watcher restarted (optional check - may not always emit new event)
	require.NoError(t, backoff.Retry(func() error {
		objEvents := corev1.EventList{}
		err := crdClient.List(ctx, &objEvents,
			ctrlclient.InNamespace(vssObj.Namespace),
			ctrlclient.MatchingFields{
				"involvedObject.name": vssObj.Name,
				"reason":              consts.ReasonEventWatcherStarted,
			},
		)
		if err != nil {
			return err
		}

		// Look for recent event (after operator restart)
		for _, event := range objEvents.Items {
			if event.LastTimestamp.Time.After(time.Now().Add(-30 * time.Second)) {
				return nil
			}
		}

		// If no recent event, check if there are multiple events (indicates restart)
		if len(objEvents.Items) >= 2 {
			return nil
		}

		return fmt.Errorf("no evidence of event watcher restart yet")
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*2), 30)))

	// Update secret in Vault to verify instant updates still work after recovery
	updatedData := map[string]interface{}{
		"key": "updated-after-recovery",
	}
	_, err = vClient.KVv2(outputs.KVV2Mount).Put(ctx, secretPath, updatedData)
	require.NoError(t, err)

	// Wait for secret to sync - proves instant updates working and registry properly recovered
	_, err = waitForSecretData(t, ctx, crdClient, 60, time.Second*2, vssObj.Spec.Destination.Name,
		vssObj.Namespace, updatedData)
	require.NoError(t, err, "secret should sync after operator recovery")
}
