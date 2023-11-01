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
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

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
		restConfig = *ctrl.GetConfigOrDie()

		os.Setenv("VAULT_ADDR", vaultAddr)
		os.Setenv("VAULT_TOKEN", vaultToken)
		os.Setenv("PATH", fmt.Sprintf("%s:%s", binDir, os.Getenv("PATH")))
		os.Exit(m.Run())
	}
}

func setCommonTFOptions(t *testing.T, opts *terraform.Options) *terraform.Options {
	t.Helper()
	if os.Getenv("SUPPRESS_TF_OUTPUT") != "" {
		opts.Logger = logger.Discard
	}
	return terraform.WithDefaultRetryableErrors(t, opts)
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

type dynamicK8SOutputs struct {
	NamePrefix       string `json:"name_prefix"`
	Namespace        string `json:"namespace"`
	K8sNamespace     string `json:"k8s_namespace"`
	K8sConfigContext string `json:"k8s_config_context"`
	AuthMount        string `json:"auth_mount"`
	AuthPolicy       string `json:"auth_policy"`
	AuthRole         string `json:"auth_role"`
	DBRole           string `json:"db_role"`
	DBRoleStatic     string `json:"db_role_static"`
	DBRoleStaticUser string `json:"db_role_static_user"`
	DBPath           string `json:"db_path"`
	TransitPath      string `json:"transit_path"`
	TransitKeyName   string `json:"transit_key_name"`
	TransitRef       string `json:"transit_ref"`
}

func assertDynamicSecret(t *testing.T, client ctrlclient.Client, maxRetries int,
	delay time.Duration, vdsObj *secretsv1beta1.VaultDynamicSecret, expected map[string]int,
) {
	t.Helper()

	namespace := vdsObj.GetNamespace()
	name := vdsObj.Spec.Destination.Name
	opts := &k8s.KubectlOptions{
		Namespace: namespace,
	}

	expectedPresentOnly := make(map[string]int)
	if vdsObj.Spec.AllowStaticCreds {
		// these keys typically have variable values that make them difficult to compare,
		// we can ensure that they are at least present and have a length > 0 in the
		// resulting Secret data.
		expectedPresentOnly[helpers.SecretDataKeyRaw] = 1
		expectedPresentOnly["last_vault_rotation"] = 1
		expectedPresentOnly["ttl"] = 1
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
				if v, ok := expectedPresentOnly[f]; ok {
					if len(b) > 0 {
						actualPresentOnly[f] = v
					}
					continue
				}
				actual[f] = len(b)
			}

			assert.Equal(t, expectedPresentOnly, actualPresentOnly)
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
	k8s.KubectlApplyFromKustomize(t, k8sOpts, kustomizeConfigPath)
	retry.DoWithRetry(t, "waitOperatorPodReady", 30, time.Millisecond*500, func() (string, error) {
		return "", k8s.RunKubectlE(t, k8sOpts,
			"wait", "--for=condition=Ready",
			"--timeout=2m", "pod", "-l", "control-plane=controller-manager")
	},
	)
}

// exportKindLogs exports the kind logs for t if exportKindLogsRoot is not empty.
// All logs are stored under exportKindLogsRoot. Every test should call this before
// undeploying the Operator from Kubernetes.
func exportKindLogs(t *testing.T) {
	t.Helper()
	if exportKindLogsRoot != "" {
		exportDir := filepath.Join(exportKindLogsRoot, t.Name())
		if testWithHelm {
			exportDir += "-helm"
		}
		if entTests {
			exportDir += "-ent"
		} else {
			exportDir += "-oss"
		}

		if t.Failed() {
			exportDir += "-failed"
		} else {
			exportDir += "-passed"
		}

		st, err := os.Stat(exportDir)
		if err != nil && !os.IsNotExist(err) {
			assert.NoError(t, err)
			return
		}

		// target path exists
		if st != nil {
			if !st.IsDir() {
				assert.Fail(t, "export path %s exists but is not a directory, cannot export logs", exportDir)
				return
			} else {
				now := time.Now().Unix()
				if err := os.Rename(exportDir, fmt.Sprintf("%s-%d", exportDir, now)); err != nil {
					assert.NoError(t, err)
					return
				}
			}
		}

		err = os.MkdirAll(exportDir, 0o755)
		if err != nil {
			assert.NoError(t, err)
			return
		}

		command := shell.Command{
			Command: "kind",
			Args:    []string{"export", "logs", "-n", clusterName, exportDir},
		}
		shell.RunCommand(t, command)
	}
}

func awaitRolloutRestarts(t *testing.T, ctx context.Context,
	client ctrlclient.Client, obj ctrlclient.Object, targets []secretsv1beta1.RolloutRestartTarget,
) {
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

func assertRolloutRestarts(
	t *testing.T, ctx context.Context, client ctrlclient.Client, obj ctrlclient.Object,
	targets []secretsv1beta1.RolloutRestartTarget, minGeneration int64,
) error {
	t.Helper()

	type status struct {
		Replicas      *int32
		ReadyReplicas int32
	}
	var errs error
	var s *status

	// see secretsv1beta1.RolloutRestartTarget for supported target resources.
	timeNow := time.Now().UTC()
	for _, target := range targets {
		var tObj ctrlclient.Object
		tObjKey := ctrlclient.ObjectKey{
			Namespace: obj.GetNamespace(),
			Name:      target.Name,
		}
		var annotations map[string]string
		switch target.Kind {
		case "Deployment":
			var o appsv1.Deployment
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
			s = &status{o.Spec.Replicas, o.Status.ReadyReplicas}
		case "StatefulSet":
			var o appsv1.StatefulSet
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
			s = &status{o.Spec.Replicas, o.Status.ReadyReplicas}
		case "ReplicaSet":
			var o appsv1.ReplicaSet
			if assert.NoError(t, client.Get(ctx, tObjKey, &o)) {
				annotations = o.Spec.Template.Annotations
				tObj = &o
			}
			s = &status{o.Spec.Replicas, o.Status.ReadyReplicas}
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

		expectedAnnotation := helpers.AnnotationRestartedAt
		val, ok := annotations[expectedAnnotation]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf("expected annotation %q not present", expectedAnnotation))
			continue
		}

		ts, err := time.Parse(time.RFC3339, val)
		if !assert.NoError(t, err,
			"invalid value for %q", expectedAnnotation) {
			continue
		}
		assert.True(t, ts.Before(timeNow),
			"timestamp value %q for %q is in the future, now=%q", ts, expectedAnnotation, timeNow)
		if s.ReadyReplicas != *s.Replicas {
			errs = errors.Join(errs, fmt.Errorf("expected ready replicas %d, actual %d", s.Replicas, s.ReadyReplicas))
		}
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

func copyModulesDir(t *testing.T, tfDir string) string {
	t.Helper()
	modulesDestDir := path.Join(tfDir, "..", "..", "modules")
	require.NoError(t, os.Mkdir(modulesDestDir, 0o755))
	require.NoError(t,
		files.CopyFolderContents(
			path.Join(testRoot, "modules"),
			modulesDestDir,
		))

	return modulesDestDir
}

func copyChartDir(t *testing.T, tfDir string) string {
	t.Helper()
	chartDestDir := path.Join(tfDir, "..", "..", "chart")
	require.NoError(t, os.Mkdir(chartDestDir, 0o755))
	require.NoError(t,
		files.CopyFolderContents(
			path.Join(testRoot, "..", "..", "chart"),
			chartDestDir,
		))
	return chartDestDir
}

func createDeployment(t *testing.T, ctx context.Context, client ctrlclient.Client, key ctrlclient.ObjectKey) *appsv1.Deployment {
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
