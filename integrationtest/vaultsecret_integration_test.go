package integrationtest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultSecret_kv(t *testing.T) {
	testNamespace := "test-tenant-1"
	testKvMountPath := "kvv2"

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: "terraform-vaultsecret-kv",
		Vars: map[string]interface{}{
			"k8s_test_namespace":  testNamespace,
			"k8s_config_context":  "kind-" + os.Getenv("KIND_CLUSTER_NAME"),
			"vault_kv_mount_path": testKvMountPath,
		},
	})

	// Clean up resources with "terraform destroy" at the end of the test.
	defer terraform.Destroy(t, terraformOptions)

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	terraform.InitAndApply(t, terraformOptions)

	// Set the secret in vault to be synced to kubernetes
	vClient := getVaultClient(t)
	putSecret := map[string]interface{}{"password": "applejuice"}
	_, err := vClient.KVv2(testKvMountPath).Put(context.Background(), "secret", putSecret)
	require.NoError(t, err)

	// Path to the Kubernetes resource config we will test.
	// TODO(tvoran): use client-go and the generated CRD types instead of yaml?
	kubeResourcePath, err := filepath.Abs("vaultsecret_kv.yaml")
	require.NoError(t, err)

	// Setup the kubectl config and context.
	options := k8s.NewKubectlOptions("kind-"+os.Getenv("KIND_CLUSTER_NAME"), "", testNamespace)

	// At the end of the test, run "kubectl delete" to clean up any resources that were created.
	defer k8s.KubectlDelete(t, options, kubeResourcePath)

	// Run `kubectl apply` to deploy. Fail the test if there are any errors.
	k8s.KubectlApply(t, options, kubeResourcePath)

	// TODO(tvoran): poll instead of sleep
	time.Sleep(10 * time.Second)

	k8s.WaitUntilSecretAvailable(t, &k8s.KubectlOptions{Namespace: testNamespace}, "secret1", 10, 1*time.Second)

	rawSecret := k8s.GetSecret(t, &k8s.KubectlOptions{Namespace: testNamespace}, "secret1")
	require.NotNil(t, rawSecret)
	require.NotEmpty(t, rawSecret.Data)

	var checkSecret map[string]interface{}
	err = json.Unmarshal(rawSecret.Data["data"], &checkSecret)
	require.NoError(t, err)
	t.Logf("secret data was %+v", checkSecret["data"])
	assert.Equal(t, putSecret, checkSecret["data"])

	// Change the secret in vault, wait for the VaultSecret refresh, and check
	// the result
	updatedSecret := map[string]interface{}{"password": "orangejuice"}
	_, err = vClient.KVv2(testKvMountPath).Put(context.Background(), "secret", updatedSecret)
	require.NoError(t, err)

	time.Sleep(10 * time.Second)

	rawSecret = k8s.GetSecret(t, &k8s.KubectlOptions{Namespace: testNamespace}, "secret1")
	require.NotNil(t, rawSecret)
	require.NotEmpty(t, rawSecret.Data)
	err = json.Unmarshal(rawSecret.Data["data"], &checkSecret)
	require.NoError(t, err)
	assert.Equal(t, updatedSecret, checkSecret["data"])
}
