// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

type fakeSyncer struct {
	requests     map[SyncRequest]int
	requeueAfter time.Duration
	count        int
	errorCount   int
	errorModulo  int
	mu           sync.RWMutex
}

func (s *fakeSyncer) Start(ctx context.Context) error {
	return nil
}

func (s *fakeSyncer) Sync(ctx context.Context, req SyncRequest) (ctrl.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.count++
	s.requests[req] = s.requests[req] + 1

	if s.errorModulo > 0 && s.count%s.errorModulo == 0 {
		s.errorCount++
		return ctrl.Result{}, fmt.Errorf("error")
	}

	return ctrl.Result{
		RequeueAfter: s.requeueAfter,
	}, nil
}

func Test_defaultSyncController_Sync(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		req            SyncRequest
		variable       bool
		requeueAfter   time.Duration
		queue          *DelegatingQueue
		want           ctrl.Result
		errorModulo    int
		wantCount      int
		wantErrorCount int
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			req: SyncRequest{
				Request: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "default",
						Name:      "success",
					},
				},
			},
			want: ctrl.Result{
				Requeue:      false,
				RequeueAfter: 0,
			},
			wantErr:   assert.NoError,
			wantCount: 10,
		},
		{
			name:     "success-variable",
			variable: true,
			req: SyncRequest{
				Request: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "default",
						Name:      "success-variable",
					},
				},
			},
			want: ctrl.Result{
				Requeue:      false,
				RequeueAfter: 0,
			},
			wantErr:   assert.NoError,
			wantCount: 10,
		},
		{
			name:     "success-variable-constant-enqueue",
			variable: true,
			req: SyncRequest{
				Request: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "default",
						Name:      "success-variable",
					},
				},
			},
			requeueAfter: time.Second * 1,
			want:         ctrl.Result{},
			wantErr:      assert.NoError,
			wantCount:    10,
		},
		{
			name: "with-failures",
			want: ctrl.Result{
				Requeue:      false,
				RequeueAfter: 0,
			},
			req: SyncRequest{
				Request: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "default",
						Name:      "with-failures",
					},
				},
			},
			wantErr:        assert.Error,
			errorModulo:    2,
			wantErrorCount: 5,
			wantCount:      10,
		},
		{
			name: "with-failures-variable",
			want: ctrl.Result{
				Requeue:      false,
				RequeueAfter: 0,
			},
			variable: true,
			req: SyncRequest{
				Request: ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: "default",
						Name:      "with-failures",
					},
				},
			},
			wantErr:        assert.Error,
			errorModulo:    2,
			wantErrorCount: 5,
			wantCount:      10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer := &fakeSyncer{
				requests:     make(map[SyncRequest]int),
				requeueAfter: tt.requeueAfter,
				errorModulo:  tt.errorModulo,
			}

			if tt.queue == nil {
				tt.queue = &DelegatingQueue{
					Interface: workqueue.New(),
				}
			}

			c := &defaultSyncController{
				do:    syncer,
				queue: tt.queue,
			}

			ctx := context.Background()
			var errs error
			wantRequests := map[SyncRequest]int{}
			for i := 0; i < tt.wantCount; i++ {
				req := tt.req
				if tt.variable {
					req = SyncRequest{
						Request: ctrl.Request{
							NamespacedName: types.NamespacedName{
								Namespace: tt.req.Namespace,
								Name:      fmt.Sprintf("%s-%d", tt.req.Name, i),
							},
						},
					}
				}
				wantRequests[req] = wantRequests[req] + 1
				got, err := c.Sync(ctx, req)
				errs = errors.Join(errs, err)
				assert.Equalf(t, tt.want, got, "Sync(%v, %v)", ctx, req)
			}

			if !tt.wantErr(t, errs, fmt.Sprintf("Sync(%v, %v)", ctx, tt.req)) {
				return
			}

			assert.Equalf(t, tt.wantCount, syncer.count, "Sync(%v, %v)", ctx, tt.req)
			var wantQueueLen int
			if tt.requeueAfter > 0 {
				wantQueueLen = len(wantRequests)
			}

			assert.Equalf(t, wantQueueLen, c.queue.Len(), "Sync(%v, %v)", ctx, tt.req)
			assert.Equalf(t, wantRequests, syncer.requests, "Sync(%v, %v)", ctx, tt.req)
			assert.Equalf(t, tt.wantErrorCount, syncer.errorCount, "Sync(%v, %v)", ctx, tt.req)
		})
	}
}

func Test_defaultSyncController_Start(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		queue              workqueue.RateLimitingInterface
		maxConcurrentSyncs int
		count              int
		do                 Syncer
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name:    "success",
			do:      &fakeSyncer{},
			count:   1,
			wantErr: assert.NoError,
		},
		{
			name:  "already-started",
			do:    &fakeSyncer{},
			count: 2,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "controller already started")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &defaultSyncController{
				do: tt.do,
				queue: workqueue.NewRateLimitingQueueWithConfig(
					workqueue.DefaultControllerRateLimiter(),
					workqueue.RateLimitingQueueConfig{
						Name: tt.name,
					},
				),
				maxConcurrentSyncs: tt.maxConcurrentSyncs,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var eg errgroup.Group
			for i := 0; i < tt.count; i++ {
				eg.Go(func() error {
					return c.Start(ctx)
				})
			}

			go func() {
				time.Sleep(1 * time.Second)
				cancel()
			}()

			if !tt.wantErr(t, eg.Wait(), fmt.Sprintf("Start(%v)", ctx)) {
				return
			}
			assert.True(t, c.started)
		})
	}
}
