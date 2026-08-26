// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

type testCaseEnqueueRefRequestHandler struct {
	name               string
	kind               ResourceKind
	refCache           *resourceReferenceCache
	syncReg            *SyncRegistry
	validator          *validatorFunc
	createEvents       []event.CreateEvent
	updateEvents       []event.UpdateEvent
	deleteEvents       []event.DeleteEvent
	q                  *DelegatingQueue
	wantQueue          []api.Request
	wantAddedAfter     []any
	wantValidCount     int
	wantValidObjects   []client.Object
	wantInvalidCount   int
	wantInvalidObjects []client.Object
	wantRefCache       *resourceReferenceCache
	maxRequeueAfter    time.Duration
}

type validatorFunc struct {
	mu             sync.Mutex
	validCount     int
	invalidCount   int
	validObjects   []client.Object
	invalidObjects []client.Object
}

func (v *validatorFunc) valid(_ context.Context, o client.Object) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.validCount++
	v.validObjects = append(v.validObjects, o)
	return nil
}

func (v *validatorFunc) invalid(_ context.Context, o client.Object) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.invalidCount++
	v.invalidObjects = append(v.invalidObjects, o)

	return errors.New("")
}

func Test_enqueueRefRequestsHandler_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	createEvent := event.CreateEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "templates",
			},
		},
	}
	cache := &resourceReferenceCache{
		m: refCacheMap{
			SecretTransformation: {
				{
					Namespace: "foo",
					Name:      "baz",
				}: map[client.ObjectKey]empty{
					client.ObjectKeyFromObject(createEvent.Object): {},
				},
			},
		},
	}
	createEvents := []event.CreateEvent{
		createEvent,
	}
	wantAddedAfterValid := []any{
		reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "foo",
				Name:      "baz",
			},
		},
	}
	tests := []testCaseEnqueueRefRequestHandler{
		{
			name:         "enqueued",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * 10,
			wantRefCache:    cache,
		},
		{
			name:         "enqueued-zero-max-horizon",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantAddedAfter: wantAddedAfterValid,
			wantRefCache:   cache,
		},
		{
			name:         "enqueued-negative-max-horizon",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * -1,
			wantRefCache:    cache,
		},
		{
			name:         "enqueued-with-validator",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			validator:    &validatorFunc{},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantValidObjects: []client.Object{
				createEvent.Object,
			},
			wantValidCount: 1,
			wantAddedAfter: wantAddedAfterValid,
			wantRefCache:   cache,
		},
		{
			name:         "not-enqueued-with-validator",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			validator:    &validatorFunc{},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantInvalidObjects: []client.Object{
				createEvent.Object,
			},
			wantInvalidCount: 1,
			wantRefCache:     cache,
		},
		{
			name: "empty-ref-cache",
			kind: SecretTransformation,
			refCache: &resourceReferenceCache{
				m: refCacheMap{},
			},
			createEvents: createEvents,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueRefRequestHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueRefRequestsHandler_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	objectOld := &secretsv1beta1.SecretTransformation{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 1,
			Namespace:  "default",
			Name:       "templates",
		},
	}
	objectNew := &secretsv1beta1.SecretTransformation{
		ObjectMeta: metav1.ObjectMeta{
			Generation: 2,
			Namespace:  "default",
			Name:       "templates",
		},
	}

	cache := &resourceReferenceCache{
		m: refCacheMap{
			SecretTransformation: {
				{
					Namespace: "foo",
					Name:      "baz",
				}: map[client.ObjectKey]empty{
					client.ObjectKeyFromObject(objectNew): {},
				},
			},
		},
	}
	updateEventsEnqueue := []event.UpdateEvent{
		{
			ObjectOld: objectOld,
			ObjectNew: objectNew,
		},
	}
	updateEventsNoEnqueue := []event.UpdateEvent{
		{
			ObjectOld: objectOld,
			ObjectNew: objectOld,
		},
	}
	wantAddedAfterValid := []any{
		reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "foo",
				Name:      "baz",
			},
		},
	}
	tests := []testCaseEnqueueRefRequestHandler{
		{
			name:         "enqueued",
			kind:         SecretTransformation,
			refCache:     cache,
			updateEvents: updateEventsEnqueue,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantAddedAfter: wantAddedAfterValid,
			wantRefCache:   cache,
		},
		{
			name:         "enqueued-with-validator",
			kind:         SecretTransformation,
			refCache:     cache,
			updateEvents: updateEventsEnqueue,
			validator:    &validatorFunc{},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantValidObjects: []client.Object{
				objectNew,
			},
			wantValidCount: 1,
			wantAddedAfter: wantAddedAfterValid,
			wantRefCache:   cache,
		},
		{
			name:         "not-enqueued-with-validator",
			kind:         SecretTransformation,
			refCache:     cache,
			updateEvents: updateEventsEnqueue,
			validator:    &validatorFunc{},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			wantInvalidObjects: []client.Object{
				objectNew,
			},
			wantInvalidCount: 1,
			wantRefCache:     cache,
		},
		{
			name: "no-enqueue-empty-ref-cache",
			kind: SecretTransformation,
			refCache: &resourceReferenceCache{
				m: refCacheMap{},
			},
			updateEvents: updateEventsEnqueue,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
		},
		{
			name:         "no-enqueue-same-generation",
			kind:         SecretTransformation,
			refCache:     cache,
			updateEvents: updateEventsNoEnqueue,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueRefRequestHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueRefRequestsHandler_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	objectOne := &secretsv1beta1.SecretTransformation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "templates",
		},
	}
	objectTwo := &secretsv1beta1.SecretTransformation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "templates2",
		},
	}

	cache := &resourceReferenceCache{
		m: refCacheMap{
			SecretTransformation: {
				{
					Namespace: "foo",
					Name:      "baz",
				}: map[client.ObjectKey]empty{
					client.ObjectKeyFromObject(objectOne): {},
				},
			},
		},
	}

	tests := []testCaseEnqueueRefRequestHandler{
		{
			name:     "not-enqueued-removed-from-cache",
			kind:     SecretTransformation,
			refCache: cache,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			deleteEvents: []event.DeleteEvent{
				{
					Object: objectOne,
				},
			},
			wantRefCache: &resourceReferenceCache{
				m: refCacheMap{},
			},
		},
		{
			name:     "not-enqueued-cache-unchanged",
			kind:     SecretTransformation,
			refCache: cache,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			deleteEvents: []event.DeleteEvent{
				{
					Object: objectTwo,
				},
			},
			wantRefCache: cache,
		},
		{
			name:     "not-enqueued-cache-update-combined",
			kind:     SecretTransformation,
			refCache: cache,
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			deleteEvents: []event.DeleteEvent{
				{
					Object: objectOne,
				},
				{
					Object: objectTwo,
				},
			},
			wantRefCache: cache,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueRefRequestHandler(t, ctx, tt)
		})
	}
}

func assertEnqueueRefRequestHandler(t *testing.T, ctx context.Context, tt testCaseEnqueueRefRequestHandler) {
	t.Helper()

	e := &enqueueRefRequestsHandler{
		kind:            tt.kind,
		refCache:        tt.refCache,
		syncReg:         tt.syncReg,
		maxRequeueAfter: tt.maxRequeueAfter,
	}

	if len(tt.createEvents) > 0 && len(tt.updateEvents) > 0 {
		require.Fail(t, "invalid test case, tt.createEvents and tt.updateEvents are mutually exclusive")
	}

	if tt.validator != nil {
		if tt.wantInvalidCount > 0 {
			e.validator = tt.validator.invalid
			require.Equal(t, tt.wantValidCount, 0)
		}
		if tt.wantValidCount > 0 {
			e.validator = tt.validator.valid
			require.Equal(t, tt.wantInvalidCount, 0)
		}
	}

	m := tt.maxRequeueAfter
	if tt.maxRequeueAfter <= 0 {
		m = maxRequeueAfter
	}

	for _, evt := range tt.createEvents {
		e.Create(ctx, evt, tt.q)
	}

	for _, evt := range tt.updateEvents {
		e.Update(ctx, evt, tt.q)
	}

	for _, evt := range tt.deleteEvents {
		e.Delete(ctx, evt, tt.q)
	}

	if assert.Equal(t, tt.wantAddedAfter, tt.q.AddedAfter) {
		if assert.Equal(t, len(tt.q.AddedAfter), len(tt.q.AddedAfterDuration)) {
			for _, d := range tt.q.AddedAfterDuration {
				assert.Greater(t, d.Seconds(), float64(0))
				assert.LessOrEqual(t, d.Seconds(), float64(m))
			}
		}
	}
	if tt.validator != nil {
		assert.Equal(t, tt.wantInvalidCount, tt.validator.invalidCount)
		assert.Equal(t, tt.wantInvalidObjects, tt.validator.invalidObjects)

		assert.Equal(t, tt.wantValidCount, tt.validator.validCount)
		assert.Equal(t, tt.wantValidObjects, tt.validator.validObjects)
	}

	if tt.wantRefCache != nil {
		assert.Equal(t, tt.wantRefCache, e.refCache)
	}
}

var _ workqueue.TypedRateLimitingInterface[reconcile.Request] = &DelegatingQueue{}

type DelegatingQueue struct {
	workqueue.TypedRateLimitingInterface[reconcile.Request]
	mu                 sync.Mutex
	AddedAfter         []any
	AddedAfterDuration []time.Duration
}

// AddAfter implements RateLimitingInterface.
func (q *DelegatingQueue) AddAfter(item reconcile.Request, d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.AddedAfter = append(q.AddedAfter, item)
	q.AddedAfterDuration = append(q.AddedAfterDuration, d)
	q.Add(item)
}

func (q *DelegatingQueue) AddRateLimited(item reconcile.Request) {}

func (q *DelegatingQueue) Forget(item reconcile.Request) {}

func (q *DelegatingQueue) NumRequeues(item reconcile.Request) int {
	return 0
}

func Test_enqueueOnDeletionRequestHandler_Delete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kind := VaultStaticSecret
	ownerRefsSupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       kind.String(),
			Name:       "baz",
		},
	}

	ownerRefsUnsupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       "Unknown",
			Name:       "foo",
		},
	}
	deleteEventSupported := event.DeleteEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsSupported,
			},
		},
	}

	deleteEventUnsupported := event.DeleteEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsUnsupported,
			},
		},
	}

	wantAddedAfterValid := []any{
		reconcile.Request{
			NamespacedName: client.ObjectKey{
				Namespace: "default",
				Name:      "baz",
			},
		},
	}

	gvk := secretsv1beta1.GroupVersion.WithKind(kind.String())
	tests := []testCaseEnqueueOnDeletionRequestHandler{
		{
			name: "enqueued",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventSupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:             gvk,
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * 10,
		},
		{
			name: "enqueued-mixed",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventUnsupported,
				deleteEventSupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:             gvk,
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * 10,
		},
		{
			name: "enqueued-mixed-zero-max-horizon",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventUnsupported,
				deleteEventSupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:            gvk,
			wantAddedAfter: wantAddedAfterValid,
		},
		{
			name: "enqueued-mixed-negative-max-horizon",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventUnsupported,
				deleteEventSupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:             gvk,
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * -1,
		},
		{
			name: "not-enqueued",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventUnsupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk: gvk,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueOnDeletionRequestHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueOnDeletionRequestHandler_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kind := VaultStaticSecret
	ownerRefsSupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       kind.String(),
			Name:       "baz",
		},
	}

	ownerRefsUnsupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       "Unknown",
			Name:       "foo",
		},
	}
	createEvent := event.CreateEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsSupported,
			},
		},
	}

	createEventUnsupported := event.CreateEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsUnsupported,
			},
		},
	}

	gvk := secretsv1beta1.GroupVersion.WithKind(kind.String())
	tests := []testCaseEnqueueOnDeletionRequestHandler{
		{
			name: "supported-not-enqueued",
			kind: kind,
			createEvents: []event.CreateEvent{
				createEvent,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
		{
			name: "unsupported-not-enqueued",
			kind: kind,
			createEvents: []event.CreateEvent{
				createEventUnsupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueOnDeletionRequestHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueOnDeletionRequestHandler_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	kind := VaultStaticSecret
	ownerRefsSupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       kind.String(),
			Name:       "baz",
		},
	}

	ownerRefsUnsupported := []metav1.OwnerReference{
		{
			APIVersion: secretsv1beta1.GroupVersion.String(),
			Kind:       "Unknown",
			Name:       "foo",
		},
	}

	updateEvent := event.UpdateEvent{
		ObjectOld: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Generation:      1,
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsSupported,
			},
		},
		ObjectNew: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Generation:      2,
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsSupported,
			},
		},
	}

	updateEventUnsupported := event.UpdateEvent{
		ObjectOld: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Generation:      1,
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsUnsupported,
			},
		},
		ObjectNew: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Generation:      2,
				Namespace:       "default",
				Name:            "vso-secret",
				OwnerReferences: ownerRefsUnsupported,
			},
		},
	}

	gvk := secretsv1beta1.GroupVersion.WithKind(kind.String())
	tests := []testCaseEnqueueOnDeletionRequestHandler{
		{
			name: "supported-not-enqueued",
			kind: kind,
			updateEvents: []event.UpdateEvent{
				updateEvent,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
		{
			name: "unsupported-not-enqueued",
			kind: kind,
			updateEvents: []event.UpdateEvent{
				updateEventUnsupported,
			},
			q: &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueOnDeletionRequestHandler(t, ctx, tt)
		})
	}
}

type testCaseEnqueueOnDeletionRequestHandler struct {
	name            string
	kind            ResourceKind
	q               *DelegatingQueue
	deleteEvents    []event.DeleteEvent
	createEvents    []event.CreateEvent
	updateEvents    []event.UpdateEvent
	wantAddedAfter  []any
	maxRequeueAfter time.Duration
	gvk             schema.GroupVersionKind
}

func assertEnqueueOnDeletionRequestHandler(t *testing.T, ctx context.Context,
	tt testCaseEnqueueOnDeletionRequestHandler,
) {
	t.Helper()

	e := &enqueueOnDeletionRequestHandler{
		gvk: tt.gvk,
	}

	m := tt.maxRequeueAfter
	if tt.maxRequeueAfter <= 0 {
		m = maxRequeueAfter
	}

	for _, evt := range tt.createEvents {
		e.Create(ctx, evt, tt.q)
	}

	for _, evt := range tt.updateEvents {
		e.Update(ctx, evt, tt.q)
	}

	for _, evt := range tt.deleteEvents {
		e.Delete(ctx, evt, tt.q)
	}

	if assert.Equal(t, tt.wantAddedAfter, tt.q.AddedAfter) {
		if assert.Equal(t, len(tt.q.AddedAfter), len(tt.q.AddedAfterDuration)) {
			for _, d := range tt.q.AddedAfterDuration {
				assert.Greater(t, d.Seconds(), float64(0))
				assert.LessOrEqual(t, d.Seconds(), float64(m))
			}
		}
	}
}

// drainQueue drains and returns every item currently in q without blocking.
// It is used to assert on items added via q.Add() (as opposed to
// q.AddAfter(), which DelegatingQueue tracks directly).
func drainQueue(q workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var reqs []reconcile.Request
	for q.Len() > 0 {
		item, _ := q.Get()
		reqs = append(reqs, item)
		q.Done(item)
	}
	return reqs
}

func newEnqueueOnDataChangeTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, secretsv1beta1.AddToScheme(s))
	return s
}

func Test_enqueueOnDataChangeRequestHandler_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	vssGVK := secretsv1beta1.GroupVersion.WithKind(VaultStaticSecret.String())
	vdsGVK := secretsv1beta1.GroupVersion.WithKind(VaultDynamicSecret.String())

	vssOwnerRef := func(name string) metav1.OwnerReference {
		return metav1.OwnerReference{
			APIVersion: vssGVK.GroupVersion().String(),
			Kind:       vssGVK.Kind,
			Name:       name,
		}
	}
	vdsOwnerRef := func(name string) metav1.OwnerReference {
		return metav1.OwnerReference{
			APIVersion: vdsGVK.GroupVersion().String(),
			Kind:       vdsGVK.Kind,
			Name:       name,
		}
	}
	unsupportedOwnerRef := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Unknown",
		Name:       "other",
	}

	secretEvent := func(refs ...metav1.OwnerReference) event.UpdateEvent {
		return event.UpdateEvent{
			ObjectOld: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "dest"},
				Data:       map[string][]byte{"foo": []byte("old")},
			},
			ObjectNew: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "default",
					Name:            "dest",
					OwnerReferences: refs,
				},
				Data: map[string][]byte{"foo": []byte("new")},
			},
		}
	}

	tests := []struct {
		name        string
		gvk         schema.GroupVersionKind
		newOwner    func() client.Object
		optIn       func(client.Object) bool
		objects     []client.Object
		evt         event.UpdateEvent
		wantEnqueue []reconcile.Request
	}{
		{
			name: "vss-hmac-enabled-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(o client.Object) bool {
				vss := o.(*secretsv1beta1.VaultStaticSecret)
				return vss.Spec.HMACSecretData != nil && *vss.Spec.HMACSecretData
			},
			objects: []client.Object{
				&secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vss1"},
					Spec:       secretsv1beta1.VaultStaticSecretSpec{HMACSecretData: ptr.To(true)},
				},
			},
			evt: secretEvent(vssOwnerRef("vss1")),
			wantEnqueue: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vss1"}},
			},
		},
		{
			name: "vss-hmac-disabled-not-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(o client.Object) bool {
				vss := o.(*secretsv1beta1.VaultStaticSecret)
				return vss.Spec.HMACSecretData != nil && *vss.Spec.HMACSecretData
			},
			objects: []client.Object{
				&secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vss1"},
					Spec:       secretsv1beta1.VaultStaticSecretSpec{HMACSecretData: ptr.To(false)},
				},
			},
			evt:         secretEvent(vssOwnerRef("vss1")),
			wantEnqueue: nil,
		},
		{
			name: "vss-hmac-unset-not-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(o client.Object) bool {
				vss := o.(*secretsv1beta1.VaultStaticSecret)
				return vss.Spec.HMACSecretData != nil && *vss.Spec.HMACSecretData
			},
			objects: []client.Object{
				&secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vss1"},
				},
			},
			evt:         secretEvent(vssOwnerRef("vss1")),
			wantEnqueue: nil,
		},
		{
			name: "vds-allow-static-creds-enabled-enqueued",
			gvk:  vdsGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultDynamicSecret{}
			},
			optIn: func(o client.Object) bool {
				vds := o.(*secretsv1beta1.VaultDynamicSecret)
				return vds.Spec.AllowStaticCreds
			},
			objects: []client.Object{
				&secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vds1"},
					Spec:       secretsv1beta1.VaultDynamicSecretSpec{AllowStaticCreds: true},
				},
			},
			evt: secretEvent(vdsOwnerRef("vds1")),
			wantEnqueue: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vds1"}},
			},
		},
		{
			name: "vds-allow-static-creds-disabled-not-enqueued",
			gvk:  vdsGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultDynamicSecret{}
			},
			optIn: func(o client.Object) bool {
				vds := o.(*secretsv1beta1.VaultDynamicSecret)
				return vds.Spec.AllowStaticCreds
			},
			objects: []client.Object{
				&secretsv1beta1.VaultDynamicSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vds1"},
					Spec:       secretsv1beta1.VaultDynamicSecretSpec{AllowStaticCreds: false},
				},
			},
			evt:         secretEvent(vdsOwnerRef("vds1")),
			wantEnqueue: nil,
		},
		{
			name: "unmatched-owner-gvk-not-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(client.Object) bool {
				return true
			},
			objects:     nil,
			evt:         secretEvent(unsupportedOwnerRef),
			wantEnqueue: nil,
		},
		{
			name: "owner-not-found-not-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(client.Object) bool {
				return true
			},
			objects:     nil,
			evt:         secretEvent(vssOwnerRef("does-not-exist")),
			wantEnqueue: nil,
		},
		{
			name: "mixed-owner-refs-only-matching-gvk-enqueued",
			gvk:  vssGVK,
			newOwner: func() client.Object {
				return &secretsv1beta1.VaultStaticSecret{}
			},
			optIn: func(o client.Object) bool {
				vss := o.(*secretsv1beta1.VaultStaticSecret)
				return vss.Spec.HMACSecretData != nil && *vss.Spec.HMACSecretData
			},
			objects: []client.Object{
				&secretsv1beta1.VaultStaticSecret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "vss1"},
					Spec:       secretsv1beta1.VaultStaticSecretSpec{HMACSecretData: ptr.To(true)},
				},
			},
			evt: secretEvent(unsupportedOwnerRef, vssOwnerRef("vss1")),
			wantEnqueue: []reconcile.Request{
				{NamespacedName: client.ObjectKey{Namespace: "default", Name: "vss1"}},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := fake.NewClientBuilder().
				WithScheme(newEnqueueOnDataChangeTestScheme(t)).
				WithObjects(tt.objects...).
				Build()

			e := &enqueueOnDataChangeRequestHandler{
				gvk:      tt.gvk,
				client:   c,
				newOwner: tt.newOwner,
				optIn:    tt.optIn,
			}

			q := &DelegatingQueue{
				TypedRateLimitingInterface: workqueue.NewTypedRateLimitingQueue[reconcile.Request](nil),
			}

			e.Update(ctx, tt.evt, q)

			assert.ElementsMatch(t, tt.wantEnqueue, drainQueue(q))

			// Create/Delete/Generic are no-ops; assert they never panic or enqueue.
			e.Create(ctx, event.CreateEvent{}, q)
			e.Delete(ctx, event.DeleteEvent{}, q)
			e.Generic(ctx, event.GenericEvent{}, q)
			assert.Empty(t, drainQueue(q))
		})
	}
}
