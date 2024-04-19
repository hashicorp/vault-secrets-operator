// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

// SecretReconciler is an interface for a controller that can reconcile secrets.
// It is a subset of the controller-runtime Reconciler interface.
type SecretReconciler interface {
	Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
	Syncer
}

// Syncer is an interface for a controller that can sync secrets.
type Syncer interface {
	Sync(ctx context.Context, req SyncRequest) (ctrl.Result, error)
	Start(ctx context.Context) error
}

// SyncControllerOptions is the options for creating a SyncController.
type SyncControllerOptions struct {
	// Name is the name of the controller. It is used for logging.
	Name string
	// Syncer is the Syncer to delegate sync requests to. It is required.
	Syncer Syncer
	// MaxConcurrentSyncs is the maximum number of concurrent syncs. It defaults to 1.
	MaxConcurrentSyncs int
}

// SyncController is an interface for a controller that can sync secrets.
type SyncController interface {
	Syncer
	Start(ctx context.Context) error
}

// NewSyncController creates a new SyncController with the given Syncer and options.
func NewSyncController(opts SyncControllerOptions) (SyncController, error) {
	maxConcurrentSyncs := opts.MaxConcurrentSyncs
	if maxConcurrentSyncs < 1 {
		maxConcurrentSyncs = 1
	}
	c := &defaultSyncController{
		do:                 opts.Syncer,
		maxConcurrentSyncs: maxConcurrentSyncs,
		queue: workqueue.NewRateLimitingQueueWithConfig(
			workqueue.DefaultControllerRateLimiter(),
			workqueue.RateLimitingQueueConfig{
				Name: opts.Name,
			},
		),
	}

	return c, nil
}

// SyncRequest is a request to sync a secret.
type SyncRequest struct {
	// Request is the reconcile request for the secret.
	ctrl.Request
	// Delay is the delay before syncing the secret.
	Delay time.Duration
	// RequeueOnErr is a flag to requeue the request on error.
	RequeueOnErr bool
}

var _ SyncController = &defaultSyncController{}

// defaultSyncController handles delegated secret reconciliation requests from a
// Syncer. The queue processing is based off of the controller-runtime
// internal/controller code, minus the k8s watchers and event handling.
type defaultSyncController struct {
	do                 Syncer
	queue              workqueue.RateLimitingInterface
	maxConcurrentSyncs int
	mu                 sync.RWMutex
	started            bool
}

// Sync implements the SyncController interface. It delegates the SyncRequest to the Syncer.
func (c *defaultSyncController) Sync(ctx context.Context, req SyncRequest) (ctrl.Result, error) {
	return ctrl.Result{}, c.syncHandler(ctx, req)
}

// Start starts the sync controller. It will start the sync workers and block
// until the context is done. It returns an error if the controller is already
// started. The context is used to stop the controller
func (c *defaultSyncController) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		return errors.New("controller already started")
	}

	go func() {
		<-ctx.Done()
		log.FromContext(ctx).Info("Shutting down sync controller")
		c.queue.ShutDown()
	}()

	wg := &sync.WaitGroup{}
	defer c.mu.Unlock()
	wg.Add(c.maxConcurrentSyncs)
	for i := 0; i < c.maxConcurrentSyncs; i++ {
		go func() {
			defer wg.Done()
			for c.processNextWorkItem(ctx) {
			}
		}()
	}
	c.started = true

	<-ctx.Done()
	wg.Wait()
	return nil
}

// processNextWorkItem processes the next item in the queue. It returns false if
// the queue is shutting down.
func (c *defaultSyncController) processNextWorkItem(ctx context.Context) bool {
	obj, shutdown := c.queue.Get()
	if shutdown {
		// The queue is shutting down.
		return false
	}

	defer c.queue.Done(obj)

	req, ok := obj.(SyncRequest)
	if !ok {
		log.FromContext(ctx).V(consts.LogLevelDebug).Info(
			"Dropping invalid item in queue, expected SyncRequest",
			"actual", obj)
		c.queue.Forget(obj)
	} else {
		_ = c.syncHandler(ctx, req)
	}

	return true
}

// syncHandler handles a single sync request. It delegates the request to the
// Syncer. It returns an error if the sync fails. It also handles enqueuing the
// request if SyncRequest.Request has Requeue or RequeueAfter set. When
// SyncRequest.Delay is set, the sync will happen later.
// Delayed requests are scheduled in the future, typically those would be
// scheduled outside a Reconciler's Reconile method.
func (c *defaultSyncController) syncHandler(ctx context.Context, req SyncRequest) error {
	// If the request has a delay, we need to requeue it with the delay.
	if req.Delay > 0 {
		c.queue.Forget(req)
		req.Delay = 0
		c.queue.AddAfter(req, req.Delay)
		return nil
	}

	syncID := uuid.NewUUID()
	logger := log.FromContext(ctx).WithValues("syncID", syncID,
		"name", req.Request.Name,
		"namespace", req.Request.Namespace,
	)
	ctx = log.IntoContext(ctx, logger)
	ctx = addSyncID(ctx, syncID)

	debugLogger := logger.V(consts.LogLevelDebug)
	debugLogger.Info("Syncing")
	result, err := c.do.Sync(ctx, req)
	if err != nil {
		if req.RequeueOnErr && !errors.Is(err, reconcile.TerminalError(nil)) {
			c.queue.AddRateLimited(req)
		}
		logger.Error(err, "Sync error")
		return err
	}

	switch {
	case result.RequeueAfter > 0:
		// RequeueAfter is set, requeue the request after the delay.
		debugLogger.Info(
			"Sync done", "horizon", result.RequeueAfter)
		c.queue.Forget(req)
		c.queue.AddAfter(req, result.RequeueAfter)
	case result.Requeue:
		// Requeue is set, requeue the request.
		debugLogger.Info("Sync done, requeue rate limited")
		c.queue.AddRateLimited(req)
	default:
		// Forget the request to avoid tracking failures forever.
		debugLogger.Info("Sync successful")
		c.queue.Forget(req)
	}

	return nil
}

// syncIDKey is the context key for the sync ID. It is used to correlate log messages.
type syncIDKey struct{}

// addSyncID adds the sync ID to the context. It is used to correlate log messages.
func addSyncID(ctx context.Context, reconcileID types.UID) context.Context {
	return context.WithValue(ctx, syncIDKey{}, reconcileID)
}
