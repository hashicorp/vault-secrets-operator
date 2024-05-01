// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	argorolloutsv1alpha1 "github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func TestRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	builder := newClientBuilder()
	// use one second ago timestamp to compare against rollout restartAt
	// since argo.Rollout's Spec.RestartAt rounds down to the nearest second
	// and often equals to time.Now()
	beforeRolloutRestart := time.Now().Add(-1 * time.Second)

	tests := []struct {
		name    string
		obj     ctrlclient.Object
		target  v1beta1.RolloutRestartTarget
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "invalid Kind",
			obj: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "qux",
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "invalid",
				Name: "qux",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("unsupported Kind %q", "invalid"), i...)
			},
		},
		{
			name: "DaemonSet",
			obj: &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "qux",
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "DaemonSet",
				Name: "qux",
			},
			wantErr: assert.NoError,
		},
		{
			name: "Deployment",
			obj: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "foo",
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "Deployment",
				Name: "foo",
			},
			wantErr: assert.NoError,
		},
		{
			name: "Deployment-in-pause",
			obj: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "foo",
				},
				Spec: appsv1.DeploymentSpec{
					Paused: true,
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "Deployment",
				Name: "foo",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("is paused, cannot restart it"), i...)
			},
		},
		{
			name: "StatefulSet",
			obj: &appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "bar",
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "StatefulSet",
				Name: "bar",
			},
			wantErr: assert.NoError,
		},
		{
			name: "argo.Rollout",
			obj: &argorolloutsv1alpha1.Rollout{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "fred",
				},
			},
			target: v1beta1.RolloutRestartTarget{
				Kind: "argo.Rollout",
				Name: "fred",
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			c := builder.Build()
			if tt.obj != nil {
				require.NoError(t, c.Create(ctx, tt.obj))
			}

			err := RolloutRestart(ctx, tt.obj.GetNamespace(), tt.target, c)
			if !tt.wantErr(t, err) {
				return
			}

			if err == nil {
				assertPatchedRolloutRestartObj(t, ctx, tt.obj, beforeRolloutRestart, c)
			}
		})
	}
}

func assertPatchedRolloutRestartObj(t *testing.T, ctx context.Context, obj ctrlclient.Object, beforeRolloutRestart time.Time, client ctrlclient.WithWatch) {
	t.Helper()

	objKey := ctrlclient.ObjectKeyFromObject(obj)
	require.NoError(t, client.Get(ctx, objKey, obj))

	attr := AnnotationRestartedAt
	var restartAtTime time.Time
	var restartAt string
	switch o := obj.(type) {
	case *appsv1.Deployment:
		restartAt = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *appsv1.StatefulSet:
		restartAt = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *appsv1.DaemonSet:
		restartAt = o.Spec.Template.ObjectMeta.Annotations[AnnotationRestartedAt]
	case *argorolloutsv1alpha1.Rollout:
		attr = "argo.rollout.spec.restartAt"
		restartAtTime = o.Spec.RestartAt.Time
	default:
		t.Fatalf("rollout restart object type not supported %v", o)
	}

	if restartAt != "" {
		var err error
		restartAtTime, err = time.Parse(time.RFC3339, restartAt)
		assert.NoError(t, err, "invalid value for %q", attr)
	}

	assert.True(t, restartAtTime.After(beforeRolloutRestart),
		"restartAt should be after beforeRolloutRestart",
		attr, restartAtTime, "beforeRolloutRestart", beforeRolloutRestart)
}
