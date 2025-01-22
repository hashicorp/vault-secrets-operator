// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package oom

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
)

var (
	testRoot  string
	chartPath string

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

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION_TESTS") == "" {
		os.Exit(0)
	}

	kindK8sVersion := os.Getenv("KIND_K8S_VERSION")

	kindClusterName = fmt.Sprintf("vso-oom-%d", time.Now().UnixNano())

	var err error
	var result int

	var tempDir string
	tempDir, err = os.MkdirTemp(os.TempDir(), "MainTestOOM")
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
		"--wait", "5m",
		"--name", kindClusterName,
		"--kubeconfig", kubeConfig,
	)

	if kindK8sVersion != "" {
		cmd.Args = append(cmd.Args, "--image", fmt.Sprintf("kindest/node:%s", kindK8sVersion))
	}
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

func TestOOM_Secrets(t *testing.T) {
	operatorImageRepo := os.Getenv("IMAGE_TAG_BASE")
	if operatorImageRepo == "" {
		require.Fail(t, "IMAGE_TAG_BASE is not set")
	}
	operatorImageTag := os.Getenv("VERSION")
	if operatorImageTag == "" {
		require.Fail(t, "VERSION is not set")
	}

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
		"--set", fmt.Sprintf("controller.manager.image.tag=%s", operatorImageTag),
		releaseName,
		chartPath,
	))

	var ds appsv1.DeploymentList
	assert.NoError(t, client.List(ctx, &ds,
		ctrlclient.InNamespace(vsoNamespace),
		ctrlclient.MatchingLabels{"app.kubernetes.io/instance": releaseName},
	),
	)

	require.Len(t, ds.Items, 1, "expected exactly one deployment")
	d := ds.Items[0]
	var c corev1.Container
	for _, c = range d.Spec.Template.Spec.Containers {
		if c.Name == "manager" {
			break
		}
	}

	require.NotNil(t, c, "manager container not found")

	i, ok := c.Resources.Limits.Memory().AsInt64()
	require.True(t, ok, "failed to get memory limit")
	require.Greater(t, i, int64(0), "memory limit is 0")

	secCount := i / 1024 / 1024
	require.Greater(t, secCount, int64(0), "secret count is %d", secCount)

	// 1MiB of random data
	data := make([]byte, 1024*1024)
	copied, err := rand.Read(data)
	require.NoError(t, err, "failed to generate random data")
	require.Equal(t, len(data), copied, "failed to generate enough random data")
	// create enough secrets to cause OOM (probably more than enough)
	for i := int64(0); i < secCount; i++ {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-secret-%d", i),
				Namespace: vsoNamespace,
			},
			Data: map[string][]byte{
				"secret": data,
			},
		}
		require.NoError(t, client.Create(ctx, sec))
	}

	// expect no OOM after 30 seconds
	bo := backoff.NewConstantBackOff(time.Second * 2)
	maxTries := uint64(15)
	var count uint64
	require.NoError(t, backoff.Retry(func() error {
		count += 1
		var pods corev1.PodList
		if err := client.List(ctx, &pods,
			ctrlclient.InNamespace(vsoNamespace),
			ctrlclient.MatchingLabels{
				"app.kubernetes.io/instance": releaseName,
				"control-plane":              "controller-manager",
			},
		); err != nil {
			return backoff.Permanent(err)
		}

		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods found")
		}

		for _, pod := range pods.Items {
			for _, cstat := range pod.Status.ContainerStatuses {
				if cstat.LastTerminationState.Terminated != nil {
					if cstat.LastTerminationState.Terminated.Reason == "OOMKilled" {
						return backoff.Permanent(fmt.Errorf("pod %s OOMKilled", pod.Name))
					} else {
						return backoff.Permanent(fmt.Errorf("pod %s terminated with other reason %s",
							pod.Name, cstat.LastTerminationState.Terminated.Reason))
					}
				}
			}
		}

		if count == maxTries {
			return nil
		}

		return fmt.Errorf("not done yet")
	}, backoff.WithMaxRetries(bo, maxTries)))
}
