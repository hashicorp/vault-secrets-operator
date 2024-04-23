// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func newClientBuilder() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	utilruntime.Must(argorolloutsv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme)
}

func marshalRaw(t *testing.T, d any) []byte {
	t.Helper()

	b, err := json.Marshal(d)
	require.NoError(t, err)
	return b
}

func createRolloutRestartObj(t *testing.T, ctx context.Context, namespace string, target secretsv1beta1.RolloutRestartTarget, client ctrlclient.WithWatch) ctrlclient.Object {
	t.Helper()

	objectMeta := v1.ObjectMeta{
		Namespace: namespace,
		Name:      target.Name,
	}

	var obj ctrlclient.Object
	switch target.Kind {
	case "DaemonSet":
		obj = &appsv1.DaemonSet{
			ObjectMeta: objectMeta,
		}
	case "Deployment":
		obj = &appsv1.Deployment{
			ObjectMeta: objectMeta,
		}
	case "StatefulSet":
		obj = &appsv1.StatefulSet{
			ObjectMeta: objectMeta,
		}
	case "argo.Rollout":
		switch target.APIVersion {
		case "", argorolloutsv1alpha1.RolloutGVR.GroupVersion().String():
			obj = &argorolloutsv1alpha1.Rollout{
				ObjectMeta: objectMeta,
			}
		default:
			return nil
		}
	default:
		return nil
	}
	require.NoError(t, client.Create(ctx, obj))
	return obj
}

func assertPatchedRolloutRestartObj(t *testing.T, ctx context.Context, obj ctrlclient.Object, beforeRolloutRestart time.Time, client ctrlclient.WithWatch) {
	t.Helper()

	objKey := ctrlclient.ObjectKeyFromObject(obj)
	require.NoError(t, client.Get(ctx, objKey, obj))

	attr := AnnotationRestartedAt
	var restartAt time.Time
	var restartAtStr string
	switch o := obj.(type) {
	case *appsv1.Deployment:
		restartAtStr = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *appsv1.StatefulSet:
		restartAtStr = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *appsv1.DaemonSet:
		restartAtStr = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *argorolloutsv1alpha1.Rollout:
		attr = "argo.rollout.spec.restartAt"
		restartAt = o.Spec.RestartAt.Time
	default:
		t.Fatalf("rollout restart object type not supported %v", o)
	}

	if restartAtStr != "" {
		var err error
		restartAt, err = time.Parse(time.RFC3339, restartAtStr)
		assert.NoError(t, err, "invalid value for %q", attr)
	}

	assert.True(t, restartAt.After(beforeRolloutRestart),
		"restartAt should be after beforeRolloutRestart",
		attr, restartAt, "beforeRolloutRestart", beforeRolloutRestart)
}
