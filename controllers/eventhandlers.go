// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

func NewEnqueueRefRequestsHandlerST(refCache ResourceReferenceCache, syncReg *SyncRegistry) handler.EventHandler {
	return NewEnqueueRefRequestsHandler(
		SecretTransformation, refCache, syncReg,
		ValidateSecretTransformation,
	)
}

func NewEnqueueRefRequestsHandler(kind ResourceKind, refCache ResourceReferenceCache, syncReg *SyncRegistry, validator ValidatorFunc) handler.EventHandler {
	return &enqueueRefRequestsHandler{
		kind:      kind,
		refCache:  refCache,
		syncReg:   syncReg,
		validator: validator,
	}
}

type enqueueRefRequestsHandler struct {
	kind      ResourceKind
	refCache  ResourceReferenceCache
	syncReg   *SyncRegistry
	validator ValidatorFunc
}

func (e *enqueueRefRequestsHandler) Create(ctx context.Context, evt event.CreateEvent, q workqueue.RateLimitingInterface) {
	e.enqueue(ctx, q, evt.Object)
}

func (e *enqueueRefRequestsHandler) Update(ctx context.Context, evt event.UpdateEvent, q workqueue.RateLimitingInterface) {
	if evt.ObjectNew.GetGeneration() != evt.ObjectOld.GetGeneration() {
		e.enqueue(ctx, q, evt.ObjectNew)
	}
}

func (e *enqueueRefRequestsHandler) Delete(ctx context.Context, evt event.DeleteEvent, _ workqueue.RateLimitingInterface) {
	e.refCache.Remove(e.kind, client.ObjectKeyFromObject(evt.Object))
}

func (e *enqueueRefRequestsHandler) Generic(ctx context.Context, evt event.GenericEvent, _ workqueue.RateLimitingInterface) {
	return
}

func (e *enqueueRefRequestsHandler) enqueue(ctx context.Context, q workqueue.RateLimitingInterface, o client.Object) {
	logger := log.FromContext(ctx).WithName("enqueueRefRequestsHandler")
	reqs := map[reconcile.Request]empty{}
	if refs, ok := e.refCache.Get(e.kind, client.ObjectKeyFromObject(o)); ok {
		if len(refs) == 0 {
			return
		}

		if e.validator != nil {
			if err := e.validator(ctx, o); err != nil {
				logger.Error(err, "Validation failed, skipping enqueue")
				return
			}
		}

		for _, ref := range refs {
			if e.syncReg != nil {
				e.syncReg.Add(ref)
			}

			req := reconcile.Request{
				NamespacedName: ref,
			}
			if _, ok := reqs[req]; !ok {
				logger.V(consts.LogLevelTrace).Info(
					"Enqueuing", "obj", ref, "refKind", e.kind)
				q.Add(req)
				reqs[req] = empty{}
			}
		}
	}
}
