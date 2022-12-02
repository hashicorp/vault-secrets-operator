package integrationtest

import (
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
)

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - kubectl
//   - A Kubernetes cluster in which:
//   - it can use the `test` namespace
//   - Vault is deployed and accessible
//
// See `make setup-integration-test` for manual testing.
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		os.Setenv("VAULT_ADDR", "http://127.0.0.1:38300")
		os.Setenv("VAULT_TOKEN", "root")
		// TODO(tvoran): setup terraform here?
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
