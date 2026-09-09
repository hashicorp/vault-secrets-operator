// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/hashicorp/vault-secrets-operator/consts"
)

var maxRequeueAfter = time.Second * 1

// NewEnqueueRefRequestsHandlerST returns a handler.EventHandler suitable for
// triggering a secret sync based on changes to a SecretTransformation resource
// instance. It includes a ValidatorFunc that prevents the referring objects from
// being queued for reconciliation.
func NewEnqueueRefRequestsHandlerST(refCache ResourceReferenceCache, syncReg *SyncRegistry) handler.EventHandler {
	return NewEnqueueRefRequestsHandlerWithOptions(&EnqueueRefRequestOptions{
		Validator:    ValidateSecretTransformation,
		SyncRegistry: syncReg,
		RefCache:     refCache,
		Kind:         SecretTransformation,
	})
}

type EnqueueRefRequestOptions struct {
	Validator       ValidatorFunc
	MaxRequeueAfter time.Duration
	SyncRegistry    *SyncRegistry
	RefCache        ResourceReferenceCache
	Kind            ResourceKind
}

// NewEnqueueRefRequestsHandler returns a handler.EventHandler for Watchers of ResourceKind.
// Deprecated: Use NewEnqueueRefRequestsHandlerWithOptions instead.
func NewEnqueueRefRequestsHandler(kind ResourceKind, refCache ResourceReferenceCache, syncReg *SyncRegistry, validator ValidatorFunc) handler.EventHandler {
	return NewEnqueueRefRequestsHandlerWithOptions(&EnqueueRefRequestOptions{
		Kind:         kind,
		RefCache:     refCache,
		SyncRegistry: syncReg,
		Validator:    validator,
	})
}

// NewEnqueueRefRequestsHandlerWithOptions returns a handler.EventHandler for
// Watchers of ResourceKind.
func NewEnqueueRefRequestsHandlerWithOptions(opts *EnqueueRefRequestOptions) handler.EventHandler {
	return &enqueueRefRequestsHandler{
		kind:      opts.Kind,
		refCache:  opts.RefCache,
		syncReg:   opts.SyncRegistry,
		validator: opts.Validator,
	}
}

var _ handler.EventHandler = (*enqueueRefRequestsHandler)(nil)

type enqueueRefRequestsHandler struct {
	kind            ResourceKind
	refCache        ResourceReferenceCache
	syncReg         *SyncRegistry
	validator       ValidatorFunc
	maxRequeueAfter time.Duration
}

func (e *enqueueRefRequestsHandler) Create(ctx context.Context,
	evt event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	e.enqueue(ctx, q, evt.Object)
}

func (e *enqueueRefRequestsHandler) Update(ctx context.Context,
	evt event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request],
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

func (e *enqueueRefRequestsHandler) Delete(_ context.Context,
	evt event.DeleteEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	e.refCache.Prune(e.kind, client.ObjectKeyFromObject(evt.Object))
}

func (e *enqueueRefRequestsHandler) Generic(_ context.Context,
	_ event.GenericEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueRefRequestsHandler) enqueue(ctx context.Context,
	q workqueue.TypedRateLimitingInterface[reconcile.Request], o client.Object,
) {
	logger := log.FromContext(ctx).WithName(
		"enqueueRefRequestsHandler").
		WithValues("refKind", e.kind)
	reqs := map[reconcile.Request]empty{}
	d := e.maxRequeueAfter
	if d <= 0 {
		d = maxRequeueAfter
	}

	referrers := e.refCache.Get(e.kind, client.ObjectKeyFromObject(o))
	if len(referrers) == 0 {
		logger.V(consts.LogLevelDebug).Info("No referrers")
		return
	}

	if e.validator != nil {
		if err := e.validator(ctx, o); err != nil {
			logger.Error(err, "Validation failed, skipping enqueue")
			return
		}
	}

	for _, ref := range referrers {
		if e.syncReg != nil {
			e.syncReg.Add(ref)
		}

		req := reconcile.Request{
			NamespacedName: ref,
		}
		if _, ok := reqs[req]; !ok {
			_, jitter := computeMaxJitterDuration(d)
			logger.V(consts.LogLevelTrace).Info(
				"Enqueuing", "obj", ref)
			q.AddAfter(req, jitter)
			reqs[req] = empty{}
		}
	}
}

var _ handler.EventHandler = (*enqueueOnDeletionRequestHandler)(nil)

// enqueueOnDeletionRequestHandler enqueues objects whenever the
// watched/dependent object is deleted. All OwnerReferences matching gvk will be
// enqueued after some randomly computed duration up until maxRequeueAfter.
type enqueueOnDeletionRequestHandler struct {
	gvk             schema.GroupVersionKind
	maxRequeueAfter time.Duration
}

func (e *enqueueOnDeletionRequestHandler) Create(_ context.Context,
	_ event.CreateEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueOnDeletionRequestHandler) Update(_ context.Context,
	_ event.UpdateEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueOnDeletionRequestHandler) Delete(ctx context.Context,
	evt event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	logger := log.FromContext(ctx).WithName("enqueueOnDeletionRequestHandler").
		WithValues("ownerGVK", e.gvk)
	reqs := map[reconcile.Request]empty{}
	d := e.maxRequeueAfter
	if d <= 0 {
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

func (e *enqueueOnDeletionRequestHandler) Generic(ctx context.Context,
	_ event.GenericEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

var _ handler.EventHandler = (*enqueueOnDataChangeRequestHandler)(nil)

// enqueueOnDataChangeRequestHandler enqueues the owning syncable-secret custom
// resource for reconciliation when a destination Secret's .Data changes out
// of band (e.g. edited or reset by something other than VSO). It does not
// implement any drift-detection logic itself: it only decides *when* to
// trigger a reconcile sooner than the next poll/requeue, letting the
// controller's existing secretMAC/HMAC comparison decide, as it already does
// on every Reconcile, whether the destination Secret actually needs to be
// repaired.
//
// Update events are expected to already be filtered to Secret.Data changes
// only (see secretDataChangedPredicate) before reaching this handler, so
// metadata-only updates (labels/annotations/resourceVersion bumps) never
// enqueue a request. For every remaining event, the owning CR (matched via
// OwnerReferences against gvk) is fetched so that optIn can decide whether
// that CR has enabled watch-driven drift detection at all; CRs that haven't
// (e.g. VaultStaticSecret with hmacSecretData=false, or VaultDynamicSecret
// with allowStaticCreds=false) are left untouched, preserving their existing
// poll/requeue-only behavior.
type enqueueOnDataChangeRequestHandler struct {
	// gvk of the owning custom resource, matched against the Secret's
	// OwnerReferences.
	gvk schema.GroupVersionKind
	// client used to fetch the owning custom resource named by a matching
	// OwnerReference, so that optIn can inspect its Spec.
	client client.Client
	// newOwner returns a new, empty instance of the owning CR type, to be
	// populated by client.Get before optIn is called.
	newOwner func() client.Object
	// optIn reports whether the just-fetched owner CR has opted in to
	// watch-driven drift detection.
	optIn func(owner client.Object) bool
}

func (e *enqueueOnDataChangeRequestHandler) Create(_ context.Context,
	_ event.CreateEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueOnDataChangeRequestHandler) Delete(_ context.Context,
	_ event.DeleteEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueOnDataChangeRequestHandler) Generic(_ context.Context,
	_ event.GenericEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
}

func (e *enqueueOnDataChangeRequestHandler) Update(ctx context.Context,
	evt event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	logger := log.FromContext(ctx).WithName("enqueueOnDataChangeRequestHandler").
		WithValues("ownerGVK", e.gvk)

	newSecret, ok := evt.ObjectNew.(*corev1.Secret)
	if !ok {
		return
	}

	for _, ref := range newSecret.GetOwnerReferences() {
		if ref.APIVersion != e.gvk.GroupVersion().String() || ref.Kind != e.gvk.Kind {
			continue
		}

		key := types.NamespacedName{
			Namespace: newSecret.GetNamespace(),
			Name:      ref.Name,
		}

		owner := e.newOwner()
		if err := e.client.Get(ctx, key, owner); err != nil {
			logger.V(consts.LogLevelDebug).Info(
				"Could not get owner for destination Secret update, skipping",
				"owner", key, "error", err)
			continue
		}

		if e.optIn != nil && !e.optIn(owner) {
			continue
		}

		logger.V(consts.LogLevelTrace).Info(
			"Enqueuing owner for destination Secret data change", "owner", key)
		q.Add(reconcile.Request{NamespacedName: key})
	}
}

// enqueueDelayingSyncEventHandler enqueues objects with a delay to avoid
// thundering herd issues. It is meant to be used with GenericEvents only.
type enqueueDelayingSyncEventHandler struct {
	enqueueDurationForJitter time.Duration
}

func (e *enqueueDelayingSyncEventHandler) Create(_ context.Context, _ event.CreateEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
}

func (e *enqueueDelayingSyncEventHandler) Update(_ context.Context, _ event.UpdateEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
}

func (e *enqueueDelayingSyncEventHandler) Delete(_ context.Context, _ event.DeleteEvent, _ workqueue.TypedRateLimitingInterface[reconcile.Request]) {
}

func (e *enqueueDelayingSyncEventHandler) Generic(ctx context.Context, evt event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	logger := log.FromContext(ctx).WithName("enqueueDelayingSyncEventHandler")
	if evt.Object == nil {
		logger.Error(nil,
			"GenericEvent received with no metadata", "event", evt)
		return
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      evt.Object.GetName(),
			Namespace: evt.Object.GetNamespace(),
		},
	}

	_, horizon := computeMaxJitterDuration(e.enqueueDurationForJitter)
	logger.V(consts.LogLevelTrace).Info("Enqueuing GenericEvent",
		"req", req, "horizon", horizon)
	if horizon > 0 {
		q.AddAfter(req, horizon)
	} else {
		q.Add(req)
	}
}
