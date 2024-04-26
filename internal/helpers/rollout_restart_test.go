// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func TestRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()
	defaultClient := clientBuilder.Build()
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
			rolloutRestartObj := createRolloutRestartObj(t, ctx, tt.args.namespace, tt.args.target, defaultClient)

			err := RolloutRestart(ctx, tt.args.namespace, tt.args.target, defaultClient)
			tt.wantErr(t, err)

			if rolloutRestartObj != nil {
				assertPatchedRolloutRestartObj(t, ctx, rolloutRestartObj, beforeRolloutRestart, defaultClient)
			}
		})
	}
}

func Test_patchForRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()
	defaultClient := clientBuilder.Build()

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
			assert.NoError(t, defaultClient.Create(ctx, tt.obj))

			tt.wantErr(t, patchForRolloutRestart(ctx, tt.obj, defaultClient))
		})
	}
}
