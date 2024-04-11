// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

type fakeSyncer struct {
	syncs      map[types.NamespacedName]SyncRequest
	count      int
	errorCount int
}

func (s *fakeSyncer) Start(ctx context.Context) error {
	// TODO implement me
	panic("implement me")
}

func (s *fakeSyncer) Sync(ctx context.Context, req SyncRequest) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func Test_defaultSyncController_Sync(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name               string
		do                 *fakeSyncer
		req                SyncRequest
		maxConcurrentSyncs int
		started            bool
		queue              workqueue.RateLimitingInterface
		want               ctrl.Result
		wantCount          int
		wantErrorCount     int
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			do:   &fakeSyncer{},
			queue: workqueue.NewRateLimitingQueueWithConfig(
				workqueue.DefaultControllerRateLimiter(),
				workqueue.RateLimitingQueueConfig{
					Name: "success",
				}),
			want: ctrl.Result{
				Requeue:      false,
				RequeueAfter: 0,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSyncController{
				do:                 tt.do,
				queue:              tt.queue,
				maxConcurrentSyncs: tt.maxConcurrentSyncs,
				started:            tt.started,
			}
			got, err := c.Sync(ctx, tt.req)
			if !tt.wantErr(t, err, fmt.Sprintf("Sync(%v, %v)", ctx, tt.req)) {
				return
			}
			assert.Equalf(t, tt.want, got, "Sync(%v, %v)", ctx, tt.req)
		})
	}
}
