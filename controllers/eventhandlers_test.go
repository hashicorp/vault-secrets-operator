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
	cache := &resourceReferenceCache{
		m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
			SecretTransformation: {
				client.ObjectKey{
					Namespace: "default",
					Name:      "templates",
				}: map[client.ObjectKey]empty{
					{
						Namespace: "foo",
						Name:      "baz",
					}: {},
				},
			},
		},
	}
	createEvent := event.CreateEvent{
		Object: &secretsv1beta1.SecretTransformation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "templates",
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
				Interface: workqueue.New(),
			},
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * 10,
			wantRefCache:    cache,
		},
		{
			name:         "enqueued-with-validator",
			kind:         SecretTransformation,
			refCache:     cache,
			createEvents: createEvents,
			validator:    &validatorFunc{},
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
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
				m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			},
			createEvents: createEvents,
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
	cache := &resourceReferenceCache{
		m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
			SecretTransformation: {
				client.ObjectKey{
					Namespace: "default",
					Name:      "templates",
				}: map[client.ObjectKey]empty{
					{
						Namespace: "foo",
						Name:      "baz",
					}: {},
				},
			},
		},
	}
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
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
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
				m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			},
			updateEvents: updateEventsEnqueue,
			q: &DelegatingQueue{
				Interface: workqueue.New(),
			},
		},
		{
			name:         "no-enqueue-same-generation",
			kind:         SecretTransformation,
			refCache:     cache,
			updateEvents: updateEventsNoEnqueue,
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
		m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
			SecretTransformation: {
				client.ObjectKeyFromObject(objectOne): map[client.ObjectKey]empty{
					{
						Namespace: "foo",
						Name:      "baz",
					}: {},
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
				Interface: workqueue.New(),
			},
			deleteEvents: []event.DeleteEvent{
				{
					Object: objectOne,
				},
			},
			wantRefCache: &resourceReferenceCache{
				m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			},
		},
		{
			name:     "not-enqueued-cache-unchanged",
			kind:     SecretTransformation,
			refCache: cache,
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
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
		kind:     tt.kind,
		refCache: tt.refCache,
		syncReg:  tt.syncReg,
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
	if tt.maxRequeueAfter == 0 {
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

var _ workqueue.RateLimitingInterface = &DelegatingQueue{}

type DelegatingQueue struct {
	workqueue.Interface
	mu                 sync.Mutex
	AddedAfter         []any
	AddedAfterDuration []time.Duration
}

// AddAfter implements RateLimitingInterface.
func (q *DelegatingQueue) AddAfter(item interface{}, d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.AddedAfter = append(q.AddedAfter, item)
	q.AddedAfterDuration = append(q.AddedAfterDuration, d)
	q.Add(item)
}

func (q *DelegatingQueue) AddRateLimited(item interface{}) {}

func (q *DelegatingQueue) Forget(item interface{}) {}

func (q *DelegatingQueue) NumRequeues(item interface{}) int {
	return 0
}

func Test_enqueueOwnerOnObjectDeletionRequestHandler_Delete(t *testing.T) {
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
	tests := []testCaseEnqueueSecretsRequestHandler{
		{
			name: "enqueued",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventSupported,
			},
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
			},
			gvk:             gvk,
			wantAddedAfter:  wantAddedAfterValid,
			maxRequeueAfter: time.Second * 10,
		},
		{
			name: "not-enqueued",
			kind: kind,
			deleteEvents: []event.DeleteEvent{
				deleteEventUnsupported,
			},
			q: &DelegatingQueue{
				Interface: workqueue.New(),
			},
			gvk: gvk,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueSecretsRequestsHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueOwnerOnObjectDeletionRequestHandler_Create(t *testing.T) {
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
	tests := []testCaseEnqueueSecretsRequestHandler{
		{
			name: "supported-not-enqueued",
			kind: kind,
			createEvents: []event.CreateEvent{
				createEvent,
			},
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueSecretsRequestsHandler(t, ctx, tt)
		})
	}
}

func Test_enqueueOwnerOnObjectDeletionRequestHandler_Update(t *testing.T) {
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
	tests := []testCaseEnqueueSecretsRequestHandler{
		{
			name: "supported-not-enqueued",
			kind: kind,
			updateEvents: []event.UpdateEvent{
				updateEvent,
			},
			q: &DelegatingQueue{
				Interface: workqueue.New(),
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
				Interface: workqueue.New(),
			},
			gvk:            gvk,
			wantAddedAfter: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assertEnqueueSecretsRequestsHandler(t, ctx, tt)
		})
	}
}

type testCaseEnqueueSecretsRequestHandler struct {
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

func assertEnqueueSecretsRequestsHandler(t *testing.T, ctx context.Context, tt testCaseEnqueueSecretsRequestHandler) {
	t.Helper()

	e := &enqueueOwnerOnObjectDeletionRequestHandler{
		gvk: tt.gvk,
	}

	m := tt.maxRequeueAfter
	if tt.maxRequeueAfter == 0 {
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
