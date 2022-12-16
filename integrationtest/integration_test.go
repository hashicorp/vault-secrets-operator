// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package integrationtest

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/retry"
	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - kubectl
//   - A Kubernetes cluster in which:
//   - Vault is deployed and accessible
//
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:38300")
		os.Setenv("VAULT_TOKEN", "root")
		os.Exit(m.Run())
	}
}

func getVaultClient(t *testing.T, namespace string) *api.Client {
	t.Helper()
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if namespace != "" {
		client.SetNamespace(namespace)
	}
	return client
}

func getCRDClient(t *testing.T) client.Client {
	t.Helper()
	err := secretsv1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	k8sClient, err := client.New(config.GetConfigOrDie(), client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	return k8sClient
}

func waitForSecretData(t *testing.T, maxRetries int, delay time.Duration, name string, namespace string, expectedData map[string]interface{}) {
	destSecret := &corev1.Secret{}
	var err error
	retry.DoWithRetry(t, "wait for k8s Secret data to be synced by the operator", 10, 1*time.Second, func() (string, error) {
		destSecret, err = k8s.GetSecretE(t, &k8s.KubectlOptions{Namespace: namespace}, name)
		if err != nil {
			return "", err
		}
		if len(destSecret.Data["data"]) == 0 {
			return "", fmt.Errorf("data in secret is empty")
		}

		var secretData map[string]interface{}
		err = json.Unmarshal(destSecret.Data["data"], &secretData)
		require.NoError(t, err)
		if !reflect.DeepEqual(expectedData, secretData["data"]) {
			return "", fmt.Errorf("data in secret not synced: expected %+v, actual %+v", expectedData, secretData["data"])
		}
		return "", nil
	})
}
