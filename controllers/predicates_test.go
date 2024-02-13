// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

type testCaseAnnoLabelChanged struct {
	name                   string
	syncReg                *SyncRegistry
	evt                    event.UpdateEvent
	want                   bool
	newPredicateFunc       func(*SyncRegistry) predicate.Predicate
	wantRegistryObjectKeys []client.ObjectKey
}

func Test_annotationChangedPredicate_Update(t *testing.T) {
	t.Parallel()

	objectOldDefault := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo",
			Annotations: map[string]string{
				"foo": "baz",
			},
		},
	}
	objectNewDefault := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo",
			Annotations: map[string]string{
				"buz": "baz",
			},
		},
	}

	defaultPredicateFunc := func(syncReg *SyncRegistry) predicate.Predicate {
		return &annotationChangedPredicate{syncReg: syncReg}
	}
	tests := []testCaseAnnoLabelChanged{
		{
			name:    "update-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectNewDefault,
			},
			want: true,
			wantRegistryObjectKeys: []client.ObjectKey{
				{
					Namespace: "default",
					Name:      "foo",
				},
			},
		},
		{
			name:    "no-update-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: objectNewDefault,
				ObjectNew: objectNewDefault,
			},
			want:                   false,
			wantRegistryObjectKeys: nil,
		},
		{
			name: "update-without-sync-registry",
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectNewDefault,
			},
			want: true,
		},
		{
			name:    "no-update-without-sync-registry",
			syncReg: nil,
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectOldDefault,
			},
			want: false,
		},
		{
			name:    "no-update-nil-old-object-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: objectOldDefault,
			},
			want: false,
		},
		{
			name:    "no-update-nil-new-object-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: nil,
			},
			want: false,
		},
		{
			name:    "no-update-nil-objects-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			tt.newPredicateFunc = defaultPredicateFunc

			t.Parallel()

			assertAnnoLabelChangedOnUpdate(t, tt)
		})
	}
}

func Test_labelChangedPredicate_Update(t *testing.T) {
	objectOldDefault := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo",
			Labels: map[string]string{
				"foo": "baz",
			},
		},
	}
	objectNewDefault := &secretsv1beta1.VaultDynamicSecret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "foo",
			Labels: map[string]string{
				"buz": "baz",
			},
		},
	}
	defaultPredicateFunc := func(syncReg *SyncRegistry) predicate.Predicate {
		return &labelChangedPredicate{syncReg: syncReg}
	}

	tests := []testCaseAnnoLabelChanged{
		{
			name:    "update-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectNewDefault,
			},
			want: true,
			wantRegistryObjectKeys: []client.ObjectKey{
				{
					Namespace: "default",
					Name:      "foo",
				},
			},
		},
		{
			name: "no-update-with-sync-registry",
			evt: event.UpdateEvent{
				ObjectOld: objectNewDefault,
				ObjectNew: objectNewDefault,
			},
			want:                   false,
			wantRegistryObjectKeys: nil,
		},
		{
			name: "update-without-sync-registry",
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectNewDefault,
			},
			want: true,
		},
		{
			name: "no-update-without-sync-registry",
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: objectOldDefault,
			},
			want: false,
		},
		{
			name:    "no-update-nil-old-object-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: objectOldDefault,
			},
			want: false,
		},
		{
			name:    "no-update-nil-new-object-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: objectOldDefault,
				ObjectNew: nil,
			},
			want: false,
		},
		{
			name:    "no-update-nil-objects-with-sync-registry",
			syncReg: NewSyncRegistry(),
			evt: event.UpdateEvent{
				ObjectOld: nil,
				ObjectNew: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			tt.newPredicateFunc = defaultPredicateFunc

			t.Parallel()
			assertAnnoLabelChangedOnUpdate(t, tt)
		})
	}
}

func assertAnnoLabelChangedOnUpdate(t *testing.T, tt testCaseAnnoLabelChanged) {
	t.Helper()

	if len(tt.wantRegistryObjectKeys) > 0 && tt.syncReg == nil {
		require.Fail(t,
			"invalid test case, cannot specify wantRegistryObjectKeys when syncReg is nil")
	}

	assert.Equalf(t, tt.want, tt.newPredicateFunc(tt.syncReg).Update(tt.evt), "Update(%v)", tt.evt)
	if tt.syncReg != nil {
		assert.ElementsMatchf(t, tt.wantRegistryObjectKeys, tt.syncReg.ObjectKeys(), "Update(%v)", tt.evt)
	}
}

func Test_secretsPredicate_Delete(t *testing.T) {
	t.Parallel()

	// label setup copied from helpers.TestHasOwnerLabels()
	require.Greater(t, len(helpers.OwnerLabels), 1, "OwnerLabels global is invalid,")

	hasNotLabels := maps.Clone(helpers.OwnerLabels)
	for k := range hasNotLabels {
		delete(hasNotLabels, k)
		break
	}
	tests := []struct {
		name string
		evt  event.DeleteEvent
		want bool
	}{
		{
			name: "has",
			evt: event.DeleteEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Labels: helpers.OwnerLabels,
					},
				},
			},
			want: true,
		},
		{
			name: "has-not",
			evt: event.DeleteEvent{
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Labels: hasNotLabels,
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &secretsPredicate{}
			assert.Equalf(t, tt.want, s.Delete(tt.evt), "Delete(%v)", tt.evt)
		})
	}
}
