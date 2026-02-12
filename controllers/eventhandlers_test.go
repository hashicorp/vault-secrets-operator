// Copyright IBM Corp. 2022, 2026
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
