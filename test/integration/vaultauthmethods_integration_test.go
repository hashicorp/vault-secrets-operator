// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

const (
	envSkipAWS            = "SKIP_AWS_TESTS"
	envSkipAWSStaticCreds = "SKIP_AWS_STATIC_CREDS_TEST"
	defaultAWSRegion      = "us-east-2"
	envSkipGCP            = "SKIP_GCP_TESTS"
)

func TestVaultAuthMethods(t *testing.T) {
	if !testWithHelm {
		t.Skipf("Helm only test, and testWithHelm=%t", testWithHelm)
	}

	testID := strings.ToLower(random.UniqueId())
	testK8sNamespace := "k8s-tenant-" + testID
	testKvv2MountPath := consts.KVSecretTypeV2 + testID
	testVaultNamespace := ""
	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}
	vault_oidc_discovery_url := os.Getenv("VAULT_OIDC_DISC_URL")
	if vault_oidc_discovery_url == "" {
		vault_oidc_discovery_url = "https://kubernetes.default.svc.cluster.local"
	}
	vault_oidc_ca := os.Getenv("VAULT_OIDC_CA")
	if vault_oidc_ca == "" {
		vault_oidc_ca = "true"
	}
	appRoleMountPath := "approle"
	runAWSTests := true
	if run, _ := runAWS(t); !run {
		runAWSTests = false
	}
	runAWSStaticTest := true
	if run, _ := runAWSStaticCreds(t); !run {
		runAWSStaticTest = false
	}
	if ok, err := requiredAWSStaticCreds(); runAWSStaticTest && !ok {
		t.Logf("WARNING: Missing AWS static creds requirements: %s", err)
	}
	awsRegion := defaultAWSRegion
	if r := os.Getenv("AWS_REGION"); r != "" {
		awsRegion = r
	}
	runGCPTests := true
	if run, _ := runGCP(t); !run {
		runGCPTests = false
	}

	require.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")
	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.Nil(t, err)

	tfDir := copyTerraformDir(t, path.Join(testRoot, "vaultauthmethods/terraform"), tempDir)
	copyModulesDir(t, tfDir)
	chartDestDir := copyChartDir(t, tfDir)

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
			"approle_mount_path":           appRoleMountPath,
			"vault_oidc_discovery_url":     vault_oidc_discovery_url,
			"vault_oidc_ca":                vault_oidc_ca,
			"run_aws_tests":                runAWSTests,
			"run_aws_static_creds_test":    runAWSStaticTest,
			"test_aws_access_key_id":       os.Getenv("TEST_AWS_ACCESS_KEY_ID"),
			"test_aws_secret_access_key":   os.Getenv("TEST_AWS_SECRET_ACCESS_KEY"),
			"test_aws_session_token":       os.Getenv("TEST_AWS_SESSION_TOKEN"),
			"aws_static_creds_role":        os.Getenv("AWS_STATIC_CREDS_ROLE"),
			"irsa_assumable_role_arn":      os.Getenv("AWS_IRSA_ROLE"),
			"aws_account_id":               os.Getenv("AWS_ACCOUNT_ID"),
			"aws_region":                   awsRegion,
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

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object
	t.Cleanup(func() {
		for _, c := range created {
			// test that the custom resources can be deleted before tf destroy
			// removes the k8s namespace
			assert.Nil(t, crdClient.Delete(ctx, c))
		}
		exportKindLogs(t)
		// Clean up resources with "terraform destroy" at the end of the test.
		terraform.Destroy(t, tfOptions)
		assert.NoError(t, os.RemoveAll(tempDir))
	})

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, tfOptions)

	// Parse terraform output
	b, err := json.Marshal(terraform.OutputAll(t, tfOptions))
	require.Nil(t, err)

	var outputs authMethodsK8sOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	if runGCPTests {
		gcpTempDir, err := os.MkdirTemp(os.TempDir(), t.Name()+"-gcp")
		require.Nil(t, err)
		gcpTfDir := copyTerraformDir(t, path.Join(testRoot, "vaultauthmethods/terraform-gcp"), gcpTempDir)

		// Construct the terraform options with default retryable errors to handle the most common
		// retryable errors in terraform testing.
		gcpTfOptions := &terraform.Options{
			// Set the path to the Terraform code that will be tested.
			TerraformDir: gcpTfDir,
			Vars: map[string]interface{}{
				"test_id":                      testID,
				"k8s_vault_connection_address": testVaultAddress,
				"k8s_test_namespace":           testK8sNamespace,
				"k8s_config_context":           k8sConfigContext,
				"run_gcp_tests":                runGCPTests,
				"gcp_project_id":               os.Getenv("GCP_PROJECT"),
				"gcp_region":                   os.Getenv("GCP_REGION"),
				"vault_policy":                 outputs.VaultPolicy,
			},
		}
		if entTests {
			gcpTfOptions.Vars["vault_enterprise"] = true
			gcpTfOptions.Vars["vault_test_namespace"] = testVaultNamespace
		}
		gcpTfOptions = setCommonTFOptions(t, gcpTfOptions)
		t.Cleanup(func() {
			// Clean up GCP resources with "terraform destroy" at the end of the test
			terraform.Destroy(t, gcpTfOptions)
			assert.NoError(t, os.RemoveAll(gcpTempDir))
		})
		terraform.InitAndApply(t, gcpTfOptions)
	}

	// Set the secrets in vault to be synced to kubernetes
	vClient := getVaultClient(t, testVaultNamespace)

	// Create a jwt auth token secret
	secretName := "jwt-auth-secret"
	secretObj := createJWTTokenSecret(t, ctx, crdClient, testK8sNamespace, secretName)
	created = append(created, secretObj)

	// canRun function that waits a minute for eventual consistency with token
	// create permission in GCP
	waitForGCPConsistency := func() (bool, error) {
		key := ctrlclient.ObjectKey{
			Namespace: testK8sNamespace,
			Name:      "workload-identity-sa-" + testID,
		}
		sa, err := helpers.GetServiceAccount(ctx, crdClient, key)
		require.NoError(t, err)
		config := vault.GCPTokenExchangeConfig{
			KSA:            sa,
			GKEClusterName: os.Getenv("GKE_CLUSTER_NAME"),
			GCPProject:     os.Getenv("GCP_PROJECT"),
			Region:         os.Getenv("GCP_REGION"),
			VaultRole:      "consistency-check",
		}
		err = backoff.Retry(func() error {
			_, err := vault.GCPTokenExchange(ctx, config, crdClient)
			return err
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*2), 30))
		if err != nil {
			return false, fmt.Errorf("timed out: %w", err)
		}
		return true, nil
	}

	type testCase struct {
		shouldRun func(*testing.T) (bool, string)
		canRun    func() (bool, error)
		vaultAuth *secretsv1beta1.VaultAuth
	}
	auths := []testCase{
		{
			shouldRun: alwaysRun,
			canRun:    noRequirements,
			// Create a non-default VaultAuth CR
			vaultAuth: &secretsv1beta1.VaultAuth{
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
		},
		{
			shouldRun: alwaysRun,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
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
		},
		{
			shouldRun: alwaysRun,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-jwt-secret",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "jwt",
					Mount:     "jwt",
					JWT: &secretsv1beta1.VaultAuthConfigJWT{
						Role:      outputs.AuthRole,
						SecretRef: secretName,
					},
				},
			},
		},
		{
			shouldRun: alwaysRun,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-approle",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					// No VaultConnectionRef - using the default.
					Namespace: testVaultNamespace,
					Method:    "appRole",
					Mount:     appRoleMountPath,
					AppRole: &secretsv1beta1.VaultAuthConfigAppRole{
						RoleID:    outputs.AppRoleRoleID,
						SecretRef: "secretid",
					},
				},
			},
		},
		{
			shouldRun: runAWS,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-aws-irsa",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "aws",
					Mount:     "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:               outputs.AuthRole + "-aws-irsa",
						Region:             awsRegion,
						IRSAServiceAccount: "irsa-test",
					},
				},
			},
		},
		{
			shouldRun: runAWS,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-aws-node",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "aws",
					Mount:     "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:   outputs.AuthRole + "-aws-node",
						Region: awsRegion,
					},
				},
			},
		},
		{
			shouldRun: runAWS,
			canRun:    noRequirements,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-aws-instance-profile",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "aws",
					Mount:     "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:   outputs.AuthRole + "-aws-instance-profile",
						Region: awsRegion,
					},
				},
			},
		},
		{
			shouldRun: runAWSStaticCreds,
			canRun:    requiredAWSStaticCreds,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-aws-static",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "aws",
					Mount:     "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:      outputs.AuthRole + "-aws-static",
						Region:    awsRegion,
						SecretRef: "aws-static-creds",
					},
				},
			},
		},
		{
			shouldRun: runGCP,
			canRun:    waitForGCPConsistency,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-gcp-workload-identity",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "gcp",
					Mount:     "gcp",
					GCP: &secretsv1beta1.VaultAuthConfigGCP{
						Role:                           outputs.AuthRole + "-gcp",
						WorkloadIdentityServiceAccount: "workload-identity-sa-" + testID,
					},
				},
			},
		},
		{
			shouldRun: runGCP,
			canRun:    waitForGCPConsistency,
			vaultAuth: &secretsv1beta1.VaultAuth{
				ObjectMeta: v1.ObjectMeta{
					Name:      "vaultauth-test-gcp-workload-identity-all-options",
					Namespace: testK8sNamespace,
				},
				Spec: secretsv1beta1.VaultAuthSpec{
					Namespace: testVaultNamespace,
					Method:    "gcp",
					Mount:     "gcp",
					GCP: &secretsv1beta1.VaultAuthConfigGCP{
						Role:                           outputs.AuthRole + "-gcp",
						Region:                         os.Getenv("GCP_REGION"),
						WorkloadIdentityServiceAccount: "workload-identity-sa-" + testID,
						ClusterName:                    os.Getenv("GKE_CLUSTER_NAME"),
						ProjectID:                      os.Getenv("GCP_PROJECT"),
					},
				},
			},
		},
	}
	expectedData := map[string]interface{}{"foo": "bar"}

	// Apply all the Auth Methods
	for _, a := range auths {
		if run, _ := a.shouldRun(t); !run {
			continue
		}
		require.Nil(t, crdClient.Create(ctx, a.vaultAuth))
		created = append(created, a.vaultAuth)
	}
	secrets := []*secretsv1beta1.VaultStaticSecret{}
	// create the VSS secrets
	for _, a := range auths {
		dest := fmt.Sprintf("kv-%s", a.vaultAuth.Name)
		secretName := fmt.Sprintf("test-secret-%s", a.vaultAuth.Name)
		secret := &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: v1.ObjectMeta{
				Name:      secretName,
				Namespace: a.vaultAuth.Namespace,
			},
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				VaultAuthRef: a.vaultAuth.Name,
				Namespace:    testVaultNamespace,
				Mount:        testKvv2MountPath,
				Type:         consts.KVSecretTypeV2,
				Path:         dest,
				Destination: secretsv1beta1.Destination{
					Name:   dest,
					Create: true,
				},
			},
		}
		secrets = append(secrets, secret)

		// Add to the created for cleanup
		if run, _ := a.shouldRun(t); run {
			created = append(created, secret)
		}
	}

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

	logEvents := func(t *testing.T, vss *secretsv1beta1.VaultStaticSecret) {
		t.Helper()

		eventList := &corev1.EventList{}
		listOptions := &client.ListOptions{
			Namespace:     vss.Namespace,
			FieldSelector: fields.OneTermEqualSelector("involvedObject.name", vss.Name),
		}
		if err := crdClient.List(ctx, eventList, listOptions); err != nil {
			t.Logf("event list error: %q", err)
			return
		}
		for _, event := range eventList.Items {
			if event.Type != corev1.EventTypeNormal {
				t.Logf("EVENT %q, name %q, reason %q, message %q", event.Type,
					event.InvolvedObject.Name, event.Reason, event.Message)
			}
		}
	}

	for idx, tt := range auths {
		t.Run(tt.vaultAuth.ObjectMeta.Name, func(t *testing.T) {
			if run, why := tt.shouldRun(t); !run {
				t.Skip(why)
			}
			if ok, err := tt.canRun(); !ok {
				assert.FailNow(t, "missing requirements: %s", err)
			}
			// Create the KV secret in Vault.
			putKV(t, secrets[idx])
			// Create the VSS object referencing the object in Vault.
			require.Nil(t, crdClient.Create(ctx, secrets[idx]))
			// Assert that the Kube secret exists + has correct Data.
			assertSync(t, secrets[idx])
			// Log events from the VaultStaticSecret to aid in debugging if the
			// test case fails
			logEvents(t, secrets[idx])
			t.Cleanup(func() {
				deleteKV(t, secrets[idx])
			})
		})
	}
}

func alwaysRun(t *testing.T) (bool, string) {
	t.Helper()
	return true, ""
}

func noRequirements() (bool, error) {
	return true, nil
}

// checks whether or not to run the aws tests
func runAWS(t *testing.T) (bool, string) {
	t.Helper()

	if v := os.Getenv(envSkipAWS); v == "true" {
		return false, "skipping because " + envSkipAWS + " is set to 'true'"
	}
	return true, ""
}

// checks whether or not to run the static creds test
func runAWSStaticCreds(t *testing.T) (bool, string) {
	t.Helper()

	if run, why := runAWS(t); !run {
		return run, why
	}
	if v := os.Getenv(envSkipAWSStaticCreds); v == "true" {
		return false, "skipping because " + envSkipAWSStaticCreds + " is set to 'true'"
	}
	return true, ""
}

func requiredAWSStaticCreds() (bool, error) {
	tfVars := []string{
		"TEST_AWS_ACCESS_KEY_ID",
		"TEST_AWS_SECRET_ACCESS_KEY",
		"AWS_STATIC_CREDS_ROLE",
	}
	var errs error
	for _, tfv := range tfVars {
		if v := os.Getenv(tfv); v == "" {
			errs = errors.Join(errs, fmt.Errorf("%q not set", tfv))
		}
	}
	if errs != nil {
		return false, errs
	}
	return true, nil
}

// checks whether or not to run the gcp tests
func runGCP(t *testing.T) (bool, string) {
	t.Helper()

	if v := os.Getenv(envSkipGCP); v == "true" {
		return false, "skipping because " + envSkipGCP + " is set to 'true'"
	}
	return true, ""
}
