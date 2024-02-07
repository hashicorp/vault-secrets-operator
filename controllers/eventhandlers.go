// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

var maxRequeueAfter = time.Second * 1

// NewEnqueueRefRequestsHandlerST returns a handler.EventHandler suitable for
// triggering a secret sync based on changes to a SecretTransformation resource
// instance. It includes a ValidatorFunc that prevents the referring objects from
// being queued for reconciliation.
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
	kind            ResourceKind
	refCache        ResourceReferenceCache
	syncReg         *SyncRegistry
	validator       ValidatorFunc
	maxRequeueAfter time.Duration
}

func (e *enqueueRefRequestsHandler) Create(ctx context.Context,
	evt event.CreateEvent, q workqueue.RateLimitingInterface,
) {
	e.enqueue(ctx, q, evt.Object)
}

func (e *enqueueRefRequestsHandler) Update(ctx context.Context,
	evt event.UpdateEvent, q workqueue.RateLimitingInterface,
) {
	if evt.ObjectOld == nil {
		return
	}
	if evt.ObjectNew == nil {
		return
	}

	if evt.ObjectNew.GetGeneration() != evt.ObjectOld.GetGeneration() {
		e.enqueue(ctx, q, evt.ObjectNew)
	}
}

func (e *enqueueRefRequestsHandler) Delete(ctx context.Context,
	evt event.DeleteEvent, _ workqueue.RateLimitingInterface,
) {
	e.refCache.Remove(e.kind, client.ObjectKeyFromObject(evt.Object))
}

func (e *enqueueRefRequestsHandler) Generic(ctx context.Context,
	_ event.GenericEvent, _ workqueue.RateLimitingInterface,
) {
	return
}

func (e *enqueueRefRequestsHandler) enqueue(ctx context.Context,
	q workqueue.RateLimitingInterface, o client.Object,
) {
	logger := log.FromContext(ctx).WithName("enqueueRefRequestsHandler")
	reqs := map[reconcile.Request]empty{}
	d := e.maxRequeueAfter
	if d == 0 {
		d = maxRequeueAfter
	}
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
				_, jitter := computeMaxJitterDuration(d)
				logger.V(consts.LogLevelTrace).Info(
					"Enqueuing", "obj", ref, "refKind", e.kind)
				q.AddAfter(req, jitter)
				reqs[req] = empty{}
			}
		}
	}
}

// enqueueOwnerOnObjectDeletionRequestHandler enqueues objects whenever the
// watched/dependent object is deleted. All OwnerReferences matching gvk will be
// enqueued after a some randomly computed duration up to maxRequeueAfter.
type enqueueOwnerOnObjectDeletionRequestHandler struct {
	gvk             schema.GroupVersionKind
	maxRequeueAfter time.Duration
}

func (e *enqueueOwnerOnObjectDeletionRequestHandler) Create(_ context.Context,
	_ event.CreateEvent, _ workqueue.RateLimitingInterface,
) {
	return
}

func (e *enqueueOwnerOnObjectDeletionRequestHandler) Update(_ context.Context,
	_ event.UpdateEvent, _ workqueue.RateLimitingInterface,
) {
	return
}

func (e *enqueueOwnerOnObjectDeletionRequestHandler) Delete(ctx context.Context,
	evt event.DeleteEvent, q workqueue.RateLimitingInterface,
) {
	logger := log.FromContext(ctx).WithName("enqueueOwnerOnObjectDeletionRequestHandler").
		WithValues("ownerGVK", e.gvk)
	reqs := map[reconcile.Request]empty{}
	d := e.maxRequeueAfter
	if d == 0 {
		d = maxRequeueAfter
	}
	for _, ref := range evt.Object.GetOwnerReferences() {
		if ref.APIVersion == e.gvk.GroupVersion().String() && ref.Kind == e.gvk.Kind {
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: evt.Object.GetNamespace(),
					Name:      ref.Name,
				},
			}
			if _, ok := reqs[req]; !ok {
				_, horizon := computeMaxJitterDuration(d)
				logger.V(consts.LogLevelTrace).Info(
					"Enqueuing", "obj", ref, "refKind", ref.Kind, "horizon", horizon)
				q.AddAfter(req, horizon)
				reqs[req] = empty{}
			}
		} else {
			logger.V(consts.LogLevelTrace).Info("No match", "ref", ref)
		}
	}
}

func (e *enqueueOwnerOnObjectDeletionRequestHandler) Generic(ctx context.Context,
	_ event.GenericEvent, _ workqueue.RateLimitingInterface,
) {
	return
}
