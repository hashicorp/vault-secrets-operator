package helpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/stretchr/testify/assert"
)

func TestRolloutRestart(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()
	defaultClient := clientBuilder.Build()
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
