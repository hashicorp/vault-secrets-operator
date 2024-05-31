// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package chart

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	ctrlruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/utils"
)

var (
	testRoot             string
	chartPath            string
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{os.Interrupt, syscall.SIGTERM}
	vsoNamespace         = "vault-secrets-operator-system"
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
	startChartVersion := os.Getenv("TEST_START_CHART_VERSION")
	if startChartVersion == "" {
		startChartVersion = "0.2.0"
	}

	// IMG is set in the Makefile
	image := os.Getenv("IMG")
	if image == "" {
		image = "hashicorp/vault-secrets-operator:0.0.0-dev"
	}

	releaseName := strings.Replace(strings.ToLower(t.Name()), "_", "-", -1)
	ctx := context.Background()
	t.Cleanup(func() {
		assert.NoError(t, uninstallVSO(t, ctx,
			"--wait",
			"--namespace", vsoNamespace,
			releaseName,
		))
	})

	require.NoError(t, runKind(t, ctx,
		"load", "docker-image", image,
		"--name", kindClusterName,
	))

	require.NoError(t, installVSO(t, ctx,
		"--wait",
		"--create-namespace",
		"--namespace", vsoNamespace,
		// picking a lower version to ensure we see some CRD changes.
		"--version", startChartVersion,
		releaseName,
		"hashicorp/vault-secrets-operator",
	))

	var origCRDs apiextensionsv1.CustomResourceDefinitionList
	require.NoError(t, client.List(ctx, &origCRDs))

	origCRDsByName := map[string]apiextensionsv1.CustomResourceDefinition{}
	for _, o := range origCRDs.Items {
		origCRDsByName[o.Name] = o
	}

	require.NoError(t, upgradeVSO(t, ctx,
		"--wait",
		"--namespace", vsoNamespace,
		"--set", "controller.manager.image.tag=0.0.0-dev",
		releaseName,
		chartPath,
	))

	crdsDir := filepath.Join(chartPath, "crds")
	wantCRDs, err := utils.LoadCRDsFromDir(crdsDir)
	require.NoError(t, err, "failed to load CRDs from %q", crdsDir)
	require.Greater(t, len(wantCRDs), 0, "no CRDs found in %q", crdsDir)

	var updatedCRDs apiextensionsv1.CustomResourceDefinitionList
	require.NoError(t, client.List(ctx, &updatedCRDs))
	assert.NotEqual(t, origCRDs.Items, updatedCRDs.Items)

	for _, wantCRD := range wantCRDs {
		var updatedCRD apiextensionsv1.CustomResourceDefinition
		require.NoError(t, client.Get(ctx, ctrlclient.ObjectKeyFromObject(&wantCRD), &updatedCRD))
		if wantCRD.Spec.Conversion == nil {
			updatedCRD.Spec.Conversion = nil
		}

		if o, ok := origCRDsByName[wantCRD.Name]; ok {
			assert.Greater(t, updatedCRD.Generation, o.Generation)
			assert.Equal(t, o.UID, updatedCRD.UID)
		} else {
			assert.Equal(t, int64(1), updatedCRD.Generation)
		}

		assert.Equal(t, wantCRD.Spec, updatedCRD.Spec, "CRD %q .spec mismatch", wantCRD.Name)
		assert.Equal(t, wantCRD.Labels, updatedCRD.Labels, "CRD %q .metadata.labels mismatch", wantCRD.Name)
		assert.Equal(t, wantCRD.Annotations, updatedCRD.Annotations, "CRD %q .metadata.annotations mismatch", wantCRD.Name)
	}
}

func installVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	ctx_, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()
	return runHelm(t, ctx_, append([]string{"install"}, extraArgs...)...)
}

func upgradeVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	ctx_, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()
	return runHelm(t, ctx_, append([]string{"upgrade"}, extraArgs...)...)
}

func uninstallVSO(t *testing.T, ctx context.Context, extraArgs ...string) error {
	t.Helper()
	ctx_, cancel := context.WithTimeout(ctx, time.Minute*3)
	defer cancel()
	return runHelm(t, ctx_, append([]string{"uninstall"}, extraArgs...)...)
}

func runHelm(t *testing.T, ctx context.Context, args ...string) error {
	t.Helper()
	return runCommand(t, ctx, "helm", args...)
}

func runKind(t *testing.T, ctx context.Context, args ...string) error {
	ctx_, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()
	t.Helper()
	return runCommand(t, ctx_, "kind", args...)
}

func runCommand(t *testing.T, ctx context.Context, name string, args ...string) error {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Running command %q", cmd)
	return cmd.Run()
}

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
