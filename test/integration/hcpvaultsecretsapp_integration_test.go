// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gruntwork-io/terratest/modules/terraform"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/client/secret_service"
	hcpconfig "github.com/hashicorp/hcp-sdk-go/config"
	hcpclient "github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/credentials/hcp"
)

type hcpVSOutputs struct {
	NamePrefix       string `json:"name_prefix"`
	K8sNamespace     string `json:"k8s_namespace"`
	K8sConfigContext string `json:"k8s_config_context"`
	SPSecretName     string `json:"sp_secret_name"`
}

func TestHCPVaultSecretsApp(t *testing.T) {
	if os.Getenv("SKIP_HCPVSAPPS_TESTS") != "" {
		t.Skipf("Skipping test, SKIP_HCPVSAPPS_TESTS is set")
	}

	if testInParallel {
		t.Parallel()
	}

	testID := "hvs"
	clusterName := os.Getenv("KIND_CLUSTER_NAME")
	assert.NotEmpty(t, clusterName, "KIND_CLUSTER_NAME is not set")

	operatorNS := os.Getenv("OPERATOR_NAMESPACE")
	assert.NotEmpty(t, operatorNS, "OPERATOR_NAMESPACE is not set")

	hcpOrganizationID := os.Getenv("HCP_ORGANIZATION_ID")
	assert.NotEmpty(t, hcpOrganizationID, "HCP_ORGANIZATION_ID is not set")

	hcpProjectID := os.Getenv("HCP_PROJECT_ID")
	assert.NotEmpty(t, hcpProjectID, "HCP_PROJECT_ID is not set")

	hcpClientID := os.Getenv("HCP_CLIENT_ID")
	assert.NotEmpty(t, hcpClientID, "HCP_CLIENT_ID is not set")

	hcpClientSecret := os.Getenv("HCP_CLIENT_SECRET")
	assert.NotEmpty(t, hcpClientSecret, "HCP_CLIENT_SECRET is not set")

	if t.Failed() {
		t.Fatal("test init failed")
	}

	hcpConfig, err := hcpconfig.NewHCPConfig(
		hcpconfig.WithProfile(&profile.UserProfile{
			OrganizationID: hcpOrganizationID,
			ProjectID:      hcpProjectID,
		}),
		hcpconfig.WithClientCredentials(hcpClientID, hcpClientSecret),
	)

	require.NoError(t, err, "failed to instantiate HCP Config")

	cl, err := hcpclient.New(hcpclient.Config{
		HCPConfig: hcpConfig,
	})
	require.NoError(t, err, "failed to instantiate HCP Client")

	hvsClient := hvsclient.New(cl, nil)

	ctx := context.Background()
	crdClient := getCRDClient(t)
	var created []ctrlclient.Object

	tempDir, err := os.MkdirTemp(os.TempDir(), t.Name())
	require.NoError(t, err)

	tfDir := copyTerraformDir(t,
		path.Join(testRoot, "hcpvaultsecretsapp/terraform"),
		tempDir,
	)
	copyModulesDirT(t, tfDir)
	chartDestDir := copyChartDirT(t, tfDir)

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
			"k8s_config_context":       k8sConfigContext,
			"name_prefix":              testID,
			"hcp_organization_id":      hcpOrganizationID,
			"hcp_project_id":           hcpProjectID,
			"hcp_client_id":            hcpClientID,
			"hcp_client_secret":        hcpClientSecret,
			"operator_helm_chart_path": chartDestDir,
			"operator_namespace":       operatorNS,
		},
	}

	tfOptions = setCommonTFOptions(t, tfOptions)
	skipCleanup := os.Getenv("SKIP_CLEANUP") != ""
	t.Cleanup(func() {
		if !skipCleanup {
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

	var outputs hcpVSOutputs
	require.Nil(t, json.Unmarshal(b, &outputs))

	auths := []*secretsv1beta1.HCPAuth{
		{
			ObjectMeta: v1.ObjectMeta{
				Name:      consts.NameDefault,
				Namespace: operatorNS,
			},
			Spec: secretsv1beta1.HCPAuthSpec{
				Method:         hcp.ProviderMethodServicePrincipal,
				OrganizationID: hcpOrganizationID,
				ProjectID:      hcpProjectID,
				ServicePrincipal: &secretsv1beta1.HCPAuthServicePrincipal{
					SecretRef: outputs.SPSecretName,
				},
			},
		},
	}

	create := func(o ctrlclient.Object) {
		require.Nil(t, crdClient.Create(ctx, o))
		created = append(created, o)
	}

	for _, o := range auths {
		create(o)
	}

	tests := []struct {
		name         string
		expectedData map[string][]byte
		updateData   map[string][]byte
	}{
		{
			name: "basic",
			expectedData: map[string][]byte{
				"foo": []byte(`baz`),
			},
		},
		{
			name: "updates",
			expectedData: map[string][]byte{
				"foo": []byte(`baz`),
			},
			updateData: map[string][]byte{
				"foo": []byte(`buz`),
			},
		},
	}

	createHVSSecrets := func(t *testing.T, appName string, data map[string][]byte) error {
		t.Helper()
		var errs error
		for k, v := range data {
			_, err := hvsClient.CreateAppKVSecret(
				hvsclient.NewCreateAppKVSecretParams().WithContext(ctx).
					WithAppName(appName).
					WithLocationOrganizationID(hcpOrganizationID).
					WithLocationProjectID(hcpProjectID).
					WithBody(
						hvsclient.CreateAppKVSecretBody{
							Name:  k,
							Value: string(v),
						}),
				nil)
			if err != nil {
				errs = errors.Join(err)
			}
		}
		return errs
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			var objsCreated []ctrlclient.Object
			// HVS restricts the length of an application name to 32 characters, so we
			// compute a unique hash for each test case. The detailed test description should
			// be included when the app is created.
			sum := sha256.Sum256([]byte(uuid.NewString()))
			appName := fmt.Sprintf("vso-test-%x", sum[len(sum)-8:])
			obj := &secretsv1beta1.HCPVaultSecretsApp{
				ObjectMeta: v1.ObjectMeta{
					Name:      appName,
					Namespace: outputs.K8sNamespace,
				},
				Spec: secretsv1beta1.HCPVaultSecretsAppSpec{
					AppName:      appName,
					RefreshAfter: "3s",
					Destination: secretsv1beta1.Destination{
						Create: true,
						Name:   appName,
					},
					RolloutRestartTargets: []secretsv1beta1.RolloutRestartTarget{
						{
							Kind: "Deployment",
							Name: appName,
						},
					},
				},
			}
			require.NoError(t, crdClient.Create(ctx, obj))
			objsCreated = append(objsCreated, obj)

			if len(obj.Spec.RolloutRestartTargets) > 0 {
				depObj := createDeployment(t, ctx, crdClient,
					ctrlclient.ObjectKey{
						Name:      appName,
						Namespace: outputs.K8sNamespace,
					},
				)
				objsCreated = append(objsCreated, depObj)
			}

			t.Cleanup(func() {
				if !skipCleanup {
					for _, obj := range objsCreated {
						assert.NoError(t, crdClient.Delete(ctx, obj))
					}

					deleteHVSApp(t, ctx, hvsClient, hcpOrganizationID, hcpProjectID, appName)
				}
			})
			_, err := hvsClient.CreateApp(
				hvsclient.NewCreateAppParams().
					WithLocationOrganizationID(hcpOrganizationID).
					WithLocationProjectID(hcpProjectID).
					WithContext(ctx).
					WithBody(hvsclient.CreateAppBody{
						Description: fmt.Sprintf("VSO test %s/%s", outputs.NamePrefix, t.Name()),
						Name:        appName,
					}), nil)
			require.NoError(t, err, "failed to create app %q", appName)

			require.NoError(t, createHVSSecrets(t, appName, tt.expectedData))

			_, err = awaitSecretSynced(t, ctx, crdClient, obj, tt.expectedData)
			if assert.NoError(t, err) {
				if len(tt.updateData) > 0 {
					require.NoError(t, createHVSSecrets(t, appName, tt.updateData))
					_, err = awaitSecretSynced(t, ctx, crdClient, obj, tt.updateData)
					if assert.NoError(t, err) {
						// check that all rollout-restarts completed successfully
						if len(obj.Spec.RolloutRestartTargets) > 0 {
							awaitRolloutRestarts(t, ctx, crdClient, obj,
								obj.Spec.RolloutRestartTargets)
						}
					}
				}
			}

			// we set a fairly large value for maxTries to help mitigate the effects of the
			// HVS' request rate limiter. Typically, the rate limiter is only ever triggered
			// when we have four or more GH workflows running concurrently.
			assertRemediationOnDestinationDeletion(t, ctx, crdClient, obj,
				time.Millisecond*500, uint64(160))
		})
	}
}

func deleteHVSApp(t *testing.T, ctx context.Context, hvsClient hvsclient.ClientService,
	orgID, projectID, appName string,
) {
	t.Helper()

	// delete all secrets so that the App can be deleted.
	resp, err := hvsClient.ListAppSecrets(
		hvsclient.NewListAppSecretsParams().
			WithContext(ctx).
			WithLocationOrganizationID(orgID).
			WithLocationProjectID(projectID).
			WithAppName(appName),
		nil)
	if assert.NoError(t, err, "failed to list secrets for app %q", appName) {
		for _, v := range resp.GetPayload().Secrets {
			_, err := hvsClient.DeleteAppSecret(
				hvsclient.NewDeleteAppSecretParams().
					WithContext(ctx).
					WithAppName(appName).
					WithLocationOrganizationID(orgID).
					WithLocationProjectID(projectID).
					WithSecretName(v.Name),
				nil)
			assert.NoError(t, err, "failed to delete secret %q in app %q",
				v.Name, appName)
		}

		_, err = hvsClient.DeleteApp(
			hvsclient.NewDeleteAppParams().
				WithContext(ctx).
				WithLocationOrganizationID(orgID).
				WithLocationProjectID(projectID).
				WithName(appName), nil)
		assert.NoError(t, err, "failed to delete app %q", appName)
	}
}
