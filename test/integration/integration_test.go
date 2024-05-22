// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/cenkalti/backoff/v4"
	"github.com/gruntwork-io/terratest/modules/files"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/retry"
	"github.com/gruntwork-io/terratest/modules/shell"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/vault"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

var (
	testRoot            string
	binDir              string
	chartPath           string
	testVaultAddress    string
	k8sVaultNamespace   string
	kustomizeConfigRoot string
	// directory to store the kind logs after each test.
	exportKindLogsRoot = os.Getenv("EXPORT_KIND_LOGS_ROOT")
	entTests           = os.Getenv("ENT_TESTS") != ""
	// use the Helm chart to deploy the operator. The default is to use Kustomize.
	testWithHelm = os.Getenv("TEST_WITH_HELM") != ""
	// make tests more verbose
	withExtraVerbosity = os.Getenv("WITH_EXTRA_VERBOSITY") != ""
	testInParallel     = os.Getenv("INTEGRATION_TESTS_PARALLEL") != ""
	// set in TestMain
	clusterName       string
	operatorImageRepo string
	operatorImageTag  string

	// extended in TestMain
	scheme = ctrlruntime.NewScheme()
	// set in TestMain
	restConfig = rest.Config{}
)

func init() {
	_, curFilePath, _, _ := runtime.Caller(0)
	testRoot = path.Dir(curFilePath)
	var err error
	binDir, err = filepath.Abs(filepath.Join(testRoot, "..", "..", "bin"))
	if err != nil {
		panic(err)
	}

	chartPath, err = filepath.Abs(filepath.Join(testRoot, "..", "..", "chart"))
	if err != nil {
		panic(err)
	}

	kustomizeConfigRoot, err = filepath.Abs(filepath.Join(testRoot, "..", "..", "build", "config"))
	if err != nil {
		panic(err)
	}

	k8sVaultNamespace = os.Getenv("K8S_VAULT_NAMESPACE")
	if k8sVaultNamespace == "" {
		k8sVaultNamespace = "vault"
	}

	testVaultAddress = fmt.Sprintf("http://vault.%s.svc.cluster.local:8200", k8sVaultNamespace)
}

// testVaultAddress is the address in k8s of the vault setup by
// `make setup-integration-test{,-ent}`

// Set the environment variable INTEGRATION_TESTS to any non-empty value to run
// the tests in this package. The test assumes it has available:
// - kubectl
//   - A Kubernetes cluster in which:
//   - Vault is deployed and accessible
//
// See `make setup-integration-test` for manual testing.
const (
	vaultToken = "root"
	vaultAddr  = "http://127.0.0.1:38300"
)

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") != "" {
		clusterName = os.Getenv("KIND_CLUSTER_NAME")
		if clusterName == "" {
			os.Stderr.WriteString("error: KIND_CLUSTER_NAME is not set\n")
			os.Exit(1)
		}
		operatorImageRepo = os.Getenv("OPERATOR_IMAGE_REPO")
		operatorImageTag = os.Getenv("OPERATOR_IMAGE_TAG")
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
		// add schemes to support other rollout restart targets
		utilruntime.Must(argorolloutsv1alpha1.AddToScheme(scheme))

		restConfig = *ctrl.GetConfigOrDie()

		os.Setenv("VAULT_ADDR", vaultAddr)
		os.Setenv("VAULT_TOKEN", vaultToken)
		os.Setenv("PATH", fmt.Sprintf("%s:%s", binDir, os.Getenv("PATH")))

	} else {
		os.Exit(0)
	}

	cleanupFunc := func() {}
	if err := os.Unsetenv("TF_PLUGIN_CACHE_DIR"); err != nil {
		os.Exit(1)
	}

	k8sConfigContext := os.Getenv("K8S_CLUSTER_CONTEXT")
	if k8sConfigContext == "" {
		k8sConfigContext = "kind-" + clusterName
	}

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	if operatorNS == "" {
		os.Exit(1)
	}

	// require.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")
	k8sOpts := &k8s.KubectlOptions{
		ContextName: k8sConfigContext,
		Namespace:   operatorNS,
	}

	kustomizeConfigPath := filepath.Join(kustomizeConfigRoot, "persistence-encrypted-test")

	tempDir, err := os.MkdirTemp(os.TempDir(), "main")
	if err != nil {
		// TODO: add log message
		log.Printf("Failed to create main tempdir, err=%s", err)
		os.Exit(1)
	}

	tfDir, err := files.CopyTerraformFolderToDest(
		path.Join(testRoot, "operator/terraform"), tempDir, "terraform")

	log.Printf("Test Root: %s", testRoot)
	_, err = copyModulesDir(tfDir)
	if err != nil {
		// TODO: add log message
		log.Printf("Failed to copy modules dir, err=%s", err)
		os.Exit(1)
	}
	chartDestDir, err := copyChartDir(tfDir)
	if err != nil {
		// TODO: add log message
		log.Printf("Failed to copy chart dir, err=%s", err)
		os.Exit(1)
	}

	// empty test case to be used with test helper functions
	t := &testing.T{}

	// Construct the terraform options with default retryable errors to handle the most common
	// retryable errors in terraform testing.
	tfOptions := setCommonTFOptions(t, &terraform.Options{
		// Set the path to the Terraform code that will be tested.
		TerraformDir: tfDir,
		Vars: map[string]interface{}{
			"k8s_vault_connection_address": testVaultAddress,
			"k8s_config_context":           k8sConfigContext,
			"k8s_vault_namespace":          k8sVaultNamespace,
			// the service account is created in test/integration/infra/main.tf
			"vault_address": os.Getenv("VAULT_ADDRESS"),
			"vault_token":   os.Getenv("VAULT_TOKEN"),
		},
	})

	b, err := json.Marshal(tfOptions.Vars)
	if err != nil {
		os.Exit(1)
	}
	if err := os.WriteFile(
		filepath.Join(tfOptions.TerraformDir, "terraform.tfvars.json"), b, 0o644); err != nil {
		os.Exit(1)
	}

	log.Printf("tfDir=%s", tfDir)
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""

	cleanupFunc = func() {
		if !skipCleanup {
			_, err := terraform.DestroyE(t, tfOptions)
			if err != nil {
				log.Printf(
					"Failed to terraform.DestroyE(t, tfOptions), err=%s", err)
			}

			if !testWithHelm {
				if err := k8s.KubectlDeleteFromKustomizeE(t, k8sOpts, kustomizeConfigPath); err != nil {
					log.Printf(
						"Failed to k8s.KubectlDeleteFromKustomizeE(t, k8sOpts, kustomizeConfigPath), err=%s", err)
				}
			}
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	ctx, cancel := setupSignalHandler()
	{
		go func() {
			select {
			case <-ctx.Done():
				cleanupFunc()
				wg.Done()
			}
		}()
	}

	var result int
	if !testWithHelm {
		if err := deployOperatorWithKustomizeE(t, k8sOpts, kustomizeConfigPath); err != nil {
			log.Printf("Failed to deployOperatorWithKustomizeE(t, k8sOpts, kustomizeConfigPath), err=%s", err)
			result = 1
		}
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

	// Run "terraform init" and "terraform apply". Fail the test if there are any errors.
	if result == 0 {
		if _, err := terraform.InitAndApplyE(t, tfOptions); err != nil {
			log.Printf("Failed to terraform.InitAndApplyE(t, tfOptions), err=%s", err)
			result = 1
		} else {
			result = m.Run()
			if err := exportKindLogs("TestMainVSO", result != 0); err != nil {
				log.Printf("Error failed to exportKindLogs(), err=%s", err)
			}
		}
	}

	cancel()
	wg.Wait()
	os.Exit(result)
}

func setCommonTFOptions(t *testing.T, opts *terraform.Options) *terraform.Options {
	t.Helper()
	if os.Getenv("SUPPRESS_TF_OUTPUT") != "" {
		opts.Logger = logger.Discard
	}

	opts = terraform.WithDefaultRetryableErrors(t, opts)
	opts.MaxRetries = 30
	opts.TimeBetweenRetries = time.Millisecond * 500
	return opts
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

func getCRDClient(t *testing.T) ctrlclient.Client {
	// restConfig is set in TestMain for when running integration tests.
	t.Helper()

	k8sClient, err := ctrlclient.New(&restConfig, ctrlclient.Options{Scheme: scheme})
	require.NoError(t, err)

	return k8sClient
}

func waitForSecretData(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, maxRetries int, delay time.Duration,
	name, namespace string, expectedData map[string]interface{},
) (*corev1.Secret, error) {
	t.Helper()
	var validSecret corev1.Secret
	secObjKey := ctrlclient.ObjectKey{Namespace: namespace, Name: name}
	_, err := retry.DoWithRetryE(t,
		fmt.Sprintf("wait for k8s Secret data to be synced by the operator, objKey=%s", secObjKey),
		maxRetries, delay, func() (string, error) {
			var err error
			var destSecret corev1.Secret
			if err := crdClient.Get(ctx, secObjKey, &destSecret); err != nil {
				return "", err
			}

			if _, ok := destSecret.Data[helpers.SecretDataKeyRaw]; !ok {
				return "", fmt.Errorf("secret hasn't been synced yet, missing '%s' field", helpers.SecretDataKeyRaw)
			}

			var rawSecret map[string]interface{}
			err = json.Unmarshal(destSecret.Data[helpers.SecretDataKeyRaw], &rawSecret)
			require.NoError(t, err)
			if _, ok := rawSecret["data"]; ok {
				rawSecret = rawSecret["data"].(map[string]interface{})
			}
			for k, v := range expectedData {
				// compare expected secret data to _raw in the k8s secret
				if !reflect.DeepEqual(v, rawSecret[k]) {
					err = errors.Join(err,
						fmt.Errorf("expected data '%s:%s' missing from %s: %#v", k, v, helpers.SecretDataKeyRaw, rawSecret))
				}
				// compare expected secret k/v to the top level items in the k8s secret
				if !reflect.DeepEqual(v, string(destSecret.Data[k])) {
					err = errors.Join(err, fmt.Errorf("expected '%s:%s', actual '%s:%s'", k, v, k, string(destSecret.Data[k])))
				}
			}
			if len(expectedData) != len(rawSecret) {
				err = errors.Join(err,
					fmt.Errorf("expected data length %d does not match %s length %d",
						len(expectedData), helpers.SecretDataKeyRaw, len(rawSecret)))
			}
			// the k8s secret has an extra key because of the "_raw" item
			if len(expectedData) != len(destSecret.Data)-1 {
				err = errors.Join(err, fmt.Errorf("expected data length %d does not match k8s secret data length %d", len(expectedData), len(destSecret.Data)-1))
			}

			if err == nil {
				validSecret = destSecret
			}

			return "", err
		})

	return &validSecret, err
}

func waitForPKIData(t *testing.T, maxRetries int, delay time.Duration, vpsObj *secretsv1beta1.VaultPKISecret, previousSerialNumber string) (string, *corev1.Secret, error) {
	t.Helper()
	destSecret := &corev1.Secret{}
	newSerialNumber, err := retry.DoWithRetryE(t, "wait for k8s Secret data to be synced by the operator", maxRetries, delay, func() (string, error) {
		var err error
		destSecret, err = k8s.GetSecretE(t,
			&k8s.KubectlOptions{Namespace: vpsObj.ObjectMeta.Namespace},
			vpsObj.Spec.Destination.Name,
		)
		if err != nil {
			return "", err
		}
		if len(destSecret.Data) == 0 {
			return "", fmt.Errorf("data in secret %s/%s is empty: %#v",
				vpsObj.ObjectMeta.Namespace, vpsObj.Spec.Destination.Name, destSecret)
		}
		for _, field := range []string{"certificate", "private_key"} {
			if len(destSecret.Data[field]) == 0 {
				return "", fmt.Errorf(field + " is empty")
			}
		}
		tlsFieldsCheck, err := checkTLSFields(destSecret)
		if vpsObj.Spec.Destination.Type == corev1.SecretTypeTLS {
			assert.True(t, tlsFieldsCheck)
			assert.NoError(t, err)
		} else {
			assert.False(t, tlsFieldsCheck)
			assert.Error(t, err)
		}

		pem, rest := pem.Decode(destSecret.Data["certificate"])
		assert.Empty(t, rest)
		cert, err := x509.ParseCertificate(pem.Bytes)
		require.NoError(t, err)
		if cert.Subject.CommonName != vpsObj.Spec.CommonName {
			return "", fmt.Errorf("subject common name %q does not match expected %q",
				cert.Subject.CommonName, vpsObj.Spec.CommonName)
		}
		if cert.SerialNumber.String() == previousSerialNumber {
			return "", fmt.Errorf("serial number %q still matches previous serial number %q", cert.SerialNumber, previousSerialNumber)
		}

		return cert.SerialNumber.String(), nil
	})

	return newSerialNumber, destSecret, err
}

// Checks that both TLS fields are present and equal to their vault response
// counterparts
func checkTLSFields(secret *corev1.Secret) (ok bool, err error) {
	var tlsCert []byte
	if tlsCert, ok = secret.Data[corev1.TLSCertKey]; !ok {
		return false, fmt.Errorf("%s is missing", corev1.TLSCertKey)
	}
	var tlsKey []byte
	if tlsKey, ok = secret.Data[corev1.TLSPrivateKeyKey]; !ok {
		return false, fmt.Errorf("%s is missing", corev1.TLSPrivateKeyKey)
	}

	certificate := secret.Data["certificate"]
	if caChain, ok := secret.Data["ca_chain"]; ok {
		certificate = append(certificate, []byte("\n")...)
		certificate = append(certificate, caChain...)
	} else if issuingCA, ok := secret.Data["issuing_ca"]; ok {
		certificate = append(certificate, []byte("\n")...)
		certificate = append(certificate, issuingCA...)
	}

	if !bytes.Equal(tlsCert, certificate) {
		return false, fmt.Errorf("%s did not equal certificate: %s, %s",
			corev1.TLSCertKey, tlsCert, secret.Data["certificate"])
	}
	if !bytes.Equal(tlsKey, secret.Data["private_key"]) {
		return false, fmt.Errorf("%s did not equal private_key: %s, %s",
			corev1.TLSPrivateKeyKey, tlsKey, secret.Data["private_key"])
	}
	return true, nil
}

type revocationK8sOutputs struct {
	AuthRole   string `json:"auth_role"`
	PolicyName string `json:"policy_name"`
}

type authMethodsK8sOutputs struct {
	AuthRole      string `json:"auth_role"`
	AppRoleRoleID string `json:"role_id"`
	GSAEmail      string `json:"gsa_email"`
	VaultPolicy   string `json:"vault_policy"`
}

func assertDynamicSecret(t *testing.T, client ctrlclient.Client, maxRetries int,
	delay time.Duration, vdsObj *secretsv1beta1.VaultDynamicSecret, expected map[string]int,
	expectedPresentOnly ...string,
) {
	t.Helper()

	namespace := vdsObj.GetNamespace()
	name := vdsObj.Spec.Destination.Name
	opts := &k8s.KubectlOptions{
		Namespace: namespace,
	}

	presentOnly := make(map[string]int)
	for _, v := range expectedPresentOnly {
		presentOnly[v] = 1
	}

	retry.DoWithRetry(t,
		"wait for dynamic secret sync", maxRetries, delay,
		func() (string, error) {
			sec, err := k8s.GetSecretE(t, opts, name)
			if err != nil {
				return "", err
			}
			if len(sec.Data) == 0 {
				return "", fmt.Errorf("empty data for secret %s: %#v", sec, sec)
			}

			actualPresentOnly := make(map[string]int)
			actual := make(map[string]int)
			for f, b := range sec.Data {
				if v, ok := presentOnly[f]; ok {
					if len(b) > 0 {
						actualPresentOnly[f] = v
					}
					continue
				}
				actual[f] = len(b)
			}

			assert.Equal(t, presentOnly, actualPresentOnly)
			assert.Equal(t, expected, actual, "actual %#v, expected %#v", actual, expected)

			assertSyncableSecret(t, client, vdsObj, sec)

			return "", nil
		})
}

func assertSyncableSecret(t *testing.T, client ctrlclient.Client, obj ctrlclient.Object, sec *corev1.Secret) {
	t.Helper()

	meta, err := common.NewSyncableSecretMetaData(obj)
	require.NoError(t, err)

	if meta.Destination.Create {
		expectedOwnerLabels, err := helpers.OwnerLabelsForObj(obj)
		if assert.NoError(t, err) {
			return
		}

		assert.Equal(t, expectedOwnerLabels, sec.Labels,
			"expected owner labels not set on %s",
			ctrlclient.ObjectKeyFromObject(sec))

		gvk, err := apiutil.GVKForObject(obj, client.Scheme())
		if !assert.NoError(t, err) {
			return
		}

		expectedAPIVersion, expectedKind := gvk.ToAPIVersionAndKind()
		// check the OwnerReferences
		expectedOwnerRefs := []v1.OwnerReference{
			{
				APIVersion: expectedAPIVersion,
				Kind:       expectedKind,
				Name:       obj.GetName(),
				UID:        obj.GetUID(),
			},
		}
		assert.Equal(t, expectedOwnerRefs, sec.OwnerReferences,
			"expected owner references not set on %s",
			ctrlclient.ObjectKeyFromObject(sec))
	} else {
		assert.Nil(t, sec.Labels,
			"expected no labels set on %s",
			ctrlclient.ObjectKeyFromObject(sec))
		assert.Nil(t, sec.OwnerReferences,
			"expected no OwnerReferences set on %s",
			ctrlclient.ObjectKeyFromObject(sec))
	}
}

func deployOperatorWithKustomize(t *testing.T, k8sOpts *k8s.KubectlOptions, kustomizeConfigPath string) {
	// deploy the Operator with Kustomize
	t.Helper()
	if err := deployOperatorWithKustomizeE(t, k8sOpts, kustomizeConfigPath); err != nil {
		t.Fatal(err)
	}
}

func deployOperatorWithKustomizeE(t *testing.T, k8sOpts *k8s.KubectlOptions, kustomizeConfigPath string) error {
	// deploy the Operator with Kustomize
	t.Helper()
	k8s.KubectlApplyFromKustomize(t, k8sOpts, kustomizeConfigPath)
	_, err := retry.DoWithRetryE(t, "waitOperatorPodReady", 30, time.Millisecond*500, func() (string, error) {
		return "", k8s.RunKubectlE(t, k8sOpts,
			"wait", "--for=condition=Ready",
			"--timeout=2m", "pod", "-l", "control-plane=controller-manager")
	},
	)
	return err
}

// exportKindLogsT exports the kind logs for t if exportKindLogsRoot is not empty.
// All logs are stored under exportKindLogsRoot. Every test should call this before
// undeploying the Operator from Kubernetes.
func exportKindLogsT(t *testing.T) {
	t.Helper()
	require.NoError(t, exportKindLogs(t.Name(), t.Failed()))
}

// exportKindLogs exports the kind logs for t if exportKindLogsRoot is not empty.
// All logs are stored under exportKindLogsRoot. Every test should call this before
// undeploying the Operator from Kubernetes.
func exportKindLogs(name string, failed bool) error {
	if exportKindLogsRoot != "" {
		exportDir := filepath.Join(exportKindLogsRoot, name)
		if testWithHelm {
			exportDir += "-helm"
		}
		if entTests {
			exportDir += "-ent"
		} else {
			exportDir += "-community"
		}

		if failed {
			exportDir += "-failed"
		} else {
			exportDir += "-passed"
		}

		st, err := os.Stat(exportDir)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		// target path exists
		if st != nil {
			if !st.IsDir() {
				return fmt.Errorf("export path %s exists but is not a directory, cannot export logs", exportDir)
			} else {
				now := time.Now().Unix()
				if err := os.Rename(exportDir, fmt.Sprintf("%s-%d", exportDir, now)); err != nil {
					return err
				}
			}
		}

		err = os.MkdirAll(exportDir, 0o755)
		if err != nil {
			return err
		}

		command := shell.Command{
			Command: "kind",
			Args:    []string{"export", "logs", "-n", clusterName, exportDir},
		}

		if err := shell.RunCommandE(&testing.T{}, command); err != nil {
			return err
		}
	}
	return nil
}

func awaitRolloutRestarts(t *testing.T, ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object, targets []secretsv1beta1.RolloutRestartTarget) {
	t.Helper()
	require.NoError(t, backoff.Retry(
		func() error {
			err := assertRolloutRestarts(t, ctx, client, obj, targets, 2)
			if t.Failed() {
				e := fmt.Errorf("assertRolloutRestarts failed")
				if err != nil {
					e = fmt.Errorf("%s, err=%w", e.Error(), err)
				}
				return backoff.Permanent(e)
			}
			return err
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*1), 60),
	))
}

// assertRolloutRestarts asserts the object state of each RolloutRestartTarget
func assertRolloutRestarts(
	t *testing.T, ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object,
	targets []secretsv1beta1.RolloutRestartTarget, minGeneration int64,
) error {
	t.Helper()

	var errs error

	// see secretsv1beta1.RolloutRestartTarget for supported target resources.
	timeNow := time.Now().UTC()
	for _, target := range targets {
		var tObj ctrlclient.Object
		tObjKey := ctrlclient.ObjectKey{
			Namespace: obj.GetNamespace(),
			Name:      target.Name,
		}
		var annotations map[string]string
		expectedAnnotation := helpers.AnnotationRestartedAt
		switch target.Kind {
		case "Deployment":
			var o appsv1.Deployment
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
		case "StatefulSet":
			var o appsv1.StatefulSet
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
		case "ReplicaSet":
			var o appsv1.ReplicaSet
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
		case "argo.Rollout":
			expectedAnnotation = "argo.rollout.status.restartedAt"

			var o argorolloutsv1alpha1.Rollout
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				tObj = &o
			}

			restartAt, err := statusAfterRestartArgoRolloutV1alpha1(&o)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			annotations = map[string]string{}
			annotations[expectedAnnotation] = restartAt.Format(time.RFC3339)
		default:
			assert.Fail(t,
				"fatal, unsupported rollout-restart Kind %q for target %v", target.Kind, target)
		}

		// expect the generation has been incremented
		if !(tObj.GetGeneration() >= minGeneration) {
			errs = errors.Join(errs, fmt.Errorf(
				"expected min generation %d, actual %d", minGeneration, tObj.GetGeneration()))
			continue
		}

		val, ok := annotations[expectedAnnotation]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf("expected annotation %q not present", expectedAnnotation))
			continue
		}
		var err error
		restartAt, err := time.Parse(time.RFC3339, val)
		if !assert.NoError(t, err,
			"invalid value for %q", expectedAnnotation) {
			continue
		}

		assert.True(t, restartAt.Before(timeNow),
			"timestamp value %q for %q is in the future, now=%q", restartAt, expectedAnnotation, timeNow)

		//if s.ReadyReplicas != *s.Replicas {
		//	errs = errors.Join(errs, fmt.Errorf("expected ready replicas %d, actual %d", s.Replicas, s.ReadyReplicas))
		//}

		/*
				=== NAME  TestVaultPKISecret/mixed/mixed-existing-0
				vaultpkisecret_integration_test.go:311:
				Error Trace:	/home/runner/work/vault-secrets-operator/vault-secrets-operator/test/integration/integration_test.go:625
				/home/runner/work/vault-secrets-operator/vault-secrets-operator/test/integration/vaultpkisecret_integration_test.go:311
			Error:      	Received unexpected error:
				expected ready replicas 824647905224, actual 2
			Test:       	TestVaultPKISecret/mixed/mixed-existing-0

		*/

	}
	return errs
}

func createJWTTokenSecret(t *testing.T, ctx context.Context, crdClient ctrlclient.Client, namespace, secretName string) *corev1.Secret {
	t.Helper()

	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: v1.ObjectMeta{
			Name:      "default",
			Namespace: namespace,
		},
	}
	tokenReq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{"vault"},
		},
	}
	require.Nil(t, crdClient.SubResource("token").Create(ctx, serviceAccount, tokenReq))
	require.NotNil(t, tokenReq.Status.Token)

	secretObj := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			vault.ProviderSecretKeyJWT: []byte(tokenReq.Status.Token),
		},
	}
	require.Nil(t, crdClient.Create(ctx, secretObj))

	return secretObj
}

func awaitSecretSynced(t *testing.T, ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object, expectedData map[string][]byte,
) (*corev1.Secret, error) {
	t.Helper()

	var s *corev1.Secret
	err := backoff.Retry(
		func() error {
			m, err := common.NewSyncableSecretMetaData(obj)
			if err != nil {
				return backoff.Permanent(err)
			}

			sec, exists, err := helpers.GetSyncableSecret(ctx, client, obj)
			if err != nil {
				return err
			} else if !exists {
				return fmt.Errorf("expected secret '%s/%s' inexistent",
					obj.GetNamespace(), m.Destination.Name,
				)
			}

			if _, ok := sec.Data[helpers.SecretDataKeyRaw]; !ok {
				return fmt.Errorf("secret hasn't been synced yet, missing '%s' field",
					helpers.SecretDataKeyRaw,
				)
			}

			actualData := make(map[string][]byte)
			for k, v := range sec.Data {
				if k == helpers.SecretDataKeyRaw {
					continue
				}
				actualData[k] = v
			}

			if !reflect.DeepEqual(actualData, expectedData) {
				return fmt.Errorf(
					"incomplete Secret data, expected=%#v, actual=%#v", expectedData, actualData)
			}

			s = sec
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*1), 30),
	)

	return s, err
}

func copyTerraformDir(t *testing.T, src, tempDest string) string {
	t.Helper()
	dir, err := files.CopyTerraformFolderToDest(src, tempDest, "terraform")
	require.NoError(t, err)
	return dir
}

func copyModulesDirT(t *testing.T, tfDir string) string {
	t.Helper()
	modulesDestDir, err := copyModulesDir(tfDir)
	require.NoError(t, err)
	return modulesDestDir
}

func copyModulesDir(tfDir string) (string, error) {
	return copyDir(
		path.Join(testRoot, "modules"),
		path.Join(tfDir, "..", "..", "modules"),
	)
}

func copyDir(srcDir, destDir string) (string, error) {
	if err := os.Mkdir(destDir, 0o755); err != nil {
		return "", err
	}

	// srcDir := path.Join(testRoot, filepath.Base(destDir))
	log.Printf("copyDir() testRoot=%s src=%s, dest=%s", testRoot, srcDir, destDir)
	if err := files.CopyFolderContents(srcDir, destDir); err != nil {
		return "", err
	}

	return destDir, nil
}

func copyChartDirT(t *testing.T, tfDir string) string {
	t.Helper()
	chartDestDir, err := copyChartDir(tfDir)
	require.NoError(t, err)
	return chartDestDir
}

func copyChartDir(tfDir string) (string, error) {
	return copyDir(
		path.Join(testRoot, "..", "..", "chart"),
		path.Join(tfDir, "..", "..", "chart"),
	)
}

func createDeployment(t *testing.T, ctx context.Context, client ctrlclient.Client,
	key ctrlclient.ObjectKey,
) *appsv1.Deployment {
	t.Helper()
	depObj := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Namespace: key.Namespace,
			Name:      key.Name,
			Labels: map[string]string{
				"test": key.Name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"test": key.Name,
				},
			},
			Replicas: pointer.Int32(3),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Labels: map[string]string{
						"test": key.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  key.Name,
							Image: "busybox:latest",
							Command: []string{
								"sh", "-c", "while : ; do sleep 10; done",
							},
						},
					},
					TerminationGracePeriodSeconds: pointer.Int64(2),
				},
			},
			Strategy: appsv1.DeploymentStrategy{
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{
						Type:   intstr.String,
						StrVal: "25%",
					},
				},
			},
		},
	}
	require.NoError(t, client.Create(ctx, depObj), "failed to create %#v", depObj)

	return depObj
}

func createArgoRolloutV1alpha1(t *testing.T, ctx context.Context, client ctrlclient.Client,
	key ctrlclient.ObjectKey,
) *argorolloutsv1alpha1.Rollout {
	t.Helper()
	rolloutObj := &argorolloutsv1alpha1.Rollout{
		ObjectMeta: v1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
		},
		Spec: argorolloutsv1alpha1.RolloutSpec{
			Selector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"test": key.Name,
				},
			},
			Replicas: pointer.Int32(2),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Labels: map[string]string{
						"test": key.Name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  key.Name,
							Image: "busybox:latest",
							Command: []string{
								"sh", "-c", "while : ; do sleep 10; done",
							},
						},
					},
					TerminationGracePeriodSeconds: pointer.Int64(2),
				},
			},
			Strategy: argorolloutsv1alpha1.RolloutStrategy{
				Canary: &argorolloutsv1alpha1.CanaryStrategy{
					Steps: []argorolloutsv1alpha1.CanaryStep{
						{
							SetWeight: pointer.Int32(50),
						},
						{
							Pause: &argorolloutsv1alpha1.RolloutPause{
								Duration: argorolloutsv1alpha1.DurationFromString("1s"),
							},
						},
					},
				},
			},
		},
	}

	require.NoError(t, client.Create(ctx, rolloutObj), "failed to create %#v", rolloutObj)

	return rolloutObj
}

func rolloutRestartObjName(secretDest, kindSuffix string) string {
	return fmt.Sprintf("%s-%s", secretDest, kindSuffix)
}

func statusAfterRestartArgoRolloutV1alpha1(o *argorolloutsv1alpha1.Rollout) (*v1.Time, error) {
	// We only do basic validation to show that VSO did the Spec.RestartAt patch.
	// We don't check that the argo.Rollout object reaches a healthy state, and
	// has Status.RestartedAt set properly, due to nondeterministic states caused by
	// argo.Rollout controller's reconciliation issues.
	// https://github.com/argoproj/argo-rollouts/issues/3418
	// https://github.com/argoproj/argo-rollouts/issues/3080
	if o.Spec.RestartAt == nil {
		return nil, fmt.Errorf("expected argo.Rollout v1alpha1 spec.restartAt not nil")
	}
	return o.Spec.RestartAt, nil
}

func assertRemediationOnDestinationDeletion(t *testing.T, ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object, delay time.Duration, maxTries uint64,
) bool {
	t.Helper()

	m, err := common.NewSyncableSecretMetaData(obj)
	if !assert.NoError(t, err, "common.NewSyncableSecretMetaData(%v)", obj) {
		return false
	}

	objKey := ctrlclient.ObjectKey{
		Namespace: obj.GetNamespace(),
		Name:      m.Destination.Name,
	}

	t.Logf("assertRemediationOnDestinationDeletion() objKey=%s, delay=%s, maxTries=%d", objKey, delay, maxTries)
	orig, err := helpers.GetSecret(ctx, client, objKey)
	if !assert.NoErrorf(t, err,
		"helpers.GetSecret(%v, %v, %v)", ctx, objKey, &orig) {
		return false
	}

	if !assert.NoError(t, client.Delete(ctx, orig)) {
		return false
	}

	return assert.NoError(t, backoff.RetryNotify(func() error {
		got, err := helpers.GetSecret(ctx, client, objKey)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return err
			} else {
				return backoff.Permanent(err)
			}
		}

		if got == nil {
			return backoff.Permanent(fmt.Errorf(
				"both secret and error are nil, should not be possible"))
		}

		if orig.GetUID() == got.GetUID() {
			return fmt.Errorf("got the same secret after deletion %s", objKey)
		}

		assert.Equal(t, orig.Labels, got.Labels)
		assert.NotEmpty(t, orig.GetUID(), "invalid Secret %v", orig)
		assert.NotEmpty(t, got.GetUID(), "invalid Secret %v", got)
		if !t.Failed() {
			assert.NotEqual(t, orig.GetUID(), got.GetUID(),
				"new Secret %v has the same UID as its predecessor %v", got, orig)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(delay), maxTries),
		func(err error, d time.Duration) {
			if withExtraVerbosity {
				t.Logf("assertRemediationOnDestinationDeletion() got error %v, retry delay=%s", err, d)
			}
		},
	))
}

var (
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{os.Interrupt, syscall.SIGTERM}
)

// // setupSignalHandler registers for SIGTERM and SIGINT. A context is returned
// // which is canceled on one of these signals. If a second signal is caught, the program
// // is terminated with exit code 1.
func setupSignalHandler() (context.Context, context.CancelFunc) {
	close(onlyOneSignalHandler) // panics when called twice

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return ctx, cancel
}
