// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package chart

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	ctrlruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
	"github.com/hashicorp/vault-secrets-operator/utils"
)

var (
	testRoot     string
	chartPath    string
	vsoNamespace = "vault-secrets-operator-system"
	// kindClusterName is set in TestMain
	kindClusterName string
	// set in TestMain
	client ctrlclient.Client
	scheme = ctrlruntime.NewScheme()
)

func init() {
	_, curFilePath, _, _ := runtime.Caller(0)
	testRoot = path.Dir(curFilePath)

	var err error
	chartPath, err = filepath.Abs(filepath.Join(testRoot, "..", "..", "chart"))
	if err != nil {
		panic(err)
	}

	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
}

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") == "" {
		os.Exit(0)
	}

	kindClusterName = fmt.Sprintf("vso-chart-%d", time.Now().UnixNano())

	var err error
	var result int

	var tempDir string
	tempDir, err = os.MkdirTemp(os.TempDir(), "MainTestChart")
	if err != nil {
		log.Printf("ERROR: Failed to create tempdir: %s", err)
		os.Exit(1)
	}

	kubeConfig := filepath.Join(tempDir, ".kube-config")
	os.Setenv("KUBECONFIG", kubeConfig)
	cleanupFunc := func() {
		if tempDir != "" {
			os.RemoveAll(tempDir)
		}

		cmd := exec.Command("kind",
			"delete", "cluster", "--name", kindClusterName,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			result = 1
			log.Printf("WARN: Failed to delete the kind cluster: %s", err)
		}
	}

	cmd := exec.Command("kind",
		"create", "cluster",
		"--name", kindClusterName,
		"--kubeconfig", kubeConfig,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	wg := sync.WaitGroup{}
	wg.Add(1)
	ctx, cancel := testutils.SetupSignalHandler()
	{
		go func() {
			select {
			case <-ctx.Done():
				cleanupFunc()
				wg.Done()
			}
		}()
	}

	err = cmd.Run()
	if err != nil {
		log.Printf("ERROR: Failed to create kind cluster: %s", err)
		os.Exit(1)
	}

	config := ctrl.GetConfigOrDie()
	client, err = ctrlclient.New(config, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		log.Printf("ERROR: Failed to setup k8s client: %s", err)
		os.Exit(1)
	}

	result = m.Run()

	cancel()
	wg.Wait()
	os.Exit(result)
}

func TestChart_upgradeCRDs(t *testing.T) {
	operatorImageRepo := os.Getenv("IMAGE_TAG_BASE")
	if operatorImageRepo == "" {
		require.Fail(t, "IMAGE_TAG_BASE is not set")
	}
	operatorImageTag := os.Getenv("VERSION")
	if operatorImageTag == "" {
		require.Fail(t, "VERSION is not set")
	}

	startChartVersion := os.Getenv("TEST_START_CHART_VERSION")
	if startChartVersion == "" {
		require.Fail(t, "TEST_START_CHART_VERSION is not set")
	}

	// incoming CRDS are used to determine if an upgrade is expected.
	b := bytes.NewBuffer([]byte{})
	chart := "hashicorp/vault-secrets-operator"
	require.NoError(t,
		testutils.RunHelm(t, context.Background(), time.Second*30, b, nil,
			"show", "crds",
			"--version", startChartVersion,
			chart,
		),
	)

	incomingCRDs, err := utils.DecodeCRDs(bytes.NewReader(b.Bytes()))
	require.NoError(t, err)
	incomingCRDsMap := map[string]apiextensionsv1.CustomResourceDefinition{}
	for _, crd := range incomingCRDs {
		incomingCRDsMap[crd.Name] = crd
	}

	crdsDir := filepath.Join(chartPath, "crds")
	wantCRDs, err := utils.LoadCRDsFromDir(crdsDir)
	require.NoError(t, err, "failed to load CRDs from %q", crdsDir)
	require.Greater(t, len(wantCRDs), 0, "no CRDs found in %q", crdsDir)

	var expectCRDUpgrade bool
	// expectUpgradeMap is used to determine if a CRD should have been upgraded.
	expectUpgradeMap := map[string]bool{}
	for _, want := range wantCRDs {
		if incoming, ok := incomingCRDsMap[want.Name]; ok {
			if reflect.DeepEqual(incoming.Spec, want.Spec) {
				// changes to annotations/labels do not result in a resource generation bump, so
				// we can unset them before comparing.
				incomingObjMetaC := incoming.ObjectMeta.DeepCopy()
				incomingObjMetaC.Annotations = nil
				incomingObjMetaC.Labels = nil
				wantObjMetaC := want.ObjectMeta.DeepCopy()
				wantObjMetaC.Annotations = nil
				wantObjMetaC.Labels = nil
				if reflect.DeepEqual(incomingObjMetaC, wantObjMetaC) {
					expectUpgradeMap[want.Name] = false
					continue
				}
			}

			expectCRDUpgrade = true
			expectUpgradeMap[want.Name] = true
		}
	}

	t.Logf("Expect upgrade from version %s: %t", startChartVersion, expectCRDUpgrade)

	image := fmt.Sprintf("%s:%s", operatorImageRepo, operatorImageTag)
	releaseName := strings.Replace(strings.ToLower(t.Name()), "_", "-", -1)
	ctx := context.Background()
	t.Cleanup(func() {
		assert.NoError(t, testutils.UninstallVSO(t, ctx,
			"--wait",
			"--namespace", vsoNamespace,
			releaseName,
		))
	})

	require.NoError(t, testutils.RunKind(t, ctx,
		"load", "docker-image", image,
		"--name", kindClusterName,
	))

	require.NoError(t, testutils.InstallVSO(t, ctx,
		"--wait",
		"--create-namespace",
		"--namespace", vsoNamespace,
		"--version", startChartVersion,
		releaseName,
		chart,
	))

	var currentCRDs apiextensionsv1.CustomResourceDefinitionList
	require.NoError(t, client.List(ctx, &currentCRDs))

	installedCRDsMap := map[string]apiextensionsv1.CustomResourceDefinition{}
	for _, o := range currentCRDs.Items {
		installedCRDsMap[o.Name] = o
	}

	require.NoError(t, testutils.UpgradeVSO(t, ctx,
		"--wait",
		"--namespace", vsoNamespace,
		"--set", fmt.Sprintf("controller.manager.image.repository=%s", operatorImageRepo),
		"--set", fmt.Sprintf("controller.manager.image.tag=%s", operatorImageTag),
		releaseName,
		chartPath,
	))

	var updatedCRDs apiextensionsv1.CustomResourceDefinitionList
	require.NoError(t, client.List(ctx, &updatedCRDs))
	if expectCRDUpgrade {
		assert.NotEqual(t, currentCRDs.Items, updatedCRDs.Items)
	}
	assert.Equal(t, len(wantCRDs), len(updatedCRDs.Items), "CRD count mismatch")

	for _, wantCRD := range wantCRDs {
		var updatedCRD apiextensionsv1.CustomResourceDefinition
		require.NoError(t, client.Get(ctx, ctrlclient.ObjectKeyFromObject(&wantCRD), &updatedCRD))
		if wantCRD.Spec.Conversion == nil {
			updatedCRD.Spec.Conversion = nil
		}

		if o, ok := installedCRDsMap[wantCRD.Name]; ok {
			if expect, _ := expectUpgradeMap[o.Name]; expect {
				assert.Greater(t, updatedCRD.Generation, o.Generation,
					"Upgrade expected, CRD %q .metadata.generation", wantCRD.Name,
				)
			} else {
				assert.Equal(t, updatedCRD.Generation, o.Generation,
					"Upgrade unexpected, CRD %q .metadata.generation", wantCRD.Name)
			}
			assert.Equal(t, o.UID, updatedCRD.UID)
		} else {
			assert.Equal(t, int64(1), updatedCRD.Generation)
		}

		assert.Equal(t, wantCRD.Spec, updatedCRD.Spec, "CRD %q .spec mismatch", wantCRD.Name)
		assert.Equal(t, wantCRD.Labels, updatedCRD.Labels, "CRD %q .metadata.labels mismatch", wantCRD.Name)
		assert.Equal(t, wantCRD.Annotations, updatedCRD.Annotations, "CRD %q .metadata.annotations mismatch", wantCRD.Name)
		assert.Len(t, updatedCRD.Status.Conditions, 2, "CRD %q .status.conditions mismatch", wantCRD.Name)
		assert.Equal(t, wantCRD.Spec.Names, updatedCRD.Status.AcceptedNames, "CRD %q .status.acceptedNames mismatch", wantCRD.Name)
		assert.Equal(t, len(updatedCRD.Status.StoredVersions), len(wantCRD.Spec.Versions), "CRD %q .status.storedVersions", wantCRD.Name)
	}
}
