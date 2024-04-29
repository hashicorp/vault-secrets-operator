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
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	builder := newClientBuilder()
	defaultClient := builder.Build()
	// use one second ago timestamp to compare against rollout restartAt
	// since argo.Rollout's Spec.RestartAt rounds down to the nearest second
	// and often equals to time.Now()
	beforeRolloutRestart := time.Now().Add(-1 * time.Second)

	type args struct {
		namespace string
		target    v1beta1.RolloutRestartTarget
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "DaemonSet",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind: "DaemonSet",
					Name: "qux",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "Deployment",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind: "Deployment",
					Name: "qux",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "StatefulSet",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind: "StatefulSet",
					Name: "qux",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "argo.Rollout empty APIVersion",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind: "argo.Rollout",
					Name: "qux",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "argo.Rollout argoproj.io/v1alpha1",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind:       "argo.Rollout",
					APIVersion: "argoproj.io/v1alpha1",
					Name:       "bar",
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "argo.Rollout invalid APIVersion",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind:       "argo.Rollout",
					APIVersion: "invalid",
					Name:       "baz",
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("unsupported APIVersion %q", "invalid"), i...)
			},
		},
		{
			name: "invalid Kind",
			args: args{
				namespace: "foo",
				target: v1beta1.RolloutRestartTarget{
					Kind: "invalid",
					Name: "baz",
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("unsupported Kind %q", "invalid"), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rolloutRestartObj := createRolloutRestartObj(t, ctx, tt.args.namespace, tt.args.target, defaultClient)

			err := RolloutRestart(ctx, tt.args.namespace, tt.args.target, defaultClient)
			if !tt.wantErr(t, err) {
				return
			}

			if rolloutRestartObj != nil {
				assertPatchedRolloutRestartObj(t, ctx, rolloutRestartObj, beforeRolloutRestart, defaultClient)
			}
		})
	}
}

func Test_patchForRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	builder := newClientBuilder()

	tests := []struct {
		name    string
		obj     client.Object
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Deployment paused",
			obj: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "bar",
				},
				Spec: appsv1.DeploymentSpec{
					Paused: true,
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					fmt.Sprintf("is paused, cannot restart it"), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := builder.Build()

			// TODO merge with TestRolloutRestart and
			assert.NoError(t, c.Create(ctx, tt.obj))

			tt.wantErr(t, patchForRolloutRestart(ctx, tt.obj, c))
		})
	}
}

func createRolloutRestartObj(t *testing.T, ctx context.Context, namespace string, target secretsv1beta1.RolloutRestartTarget, client ctrlclient.WithWatch) ctrlclient.Object {
	t.Helper()

	objectMeta := metav1.ObjectMeta{
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
