// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type resourceRefTest struct {
	referrer   client.ObjectKey
	reference  client.ObjectKey
	references []client.ObjectKey
	// action 0: Set, 1: Get, 2: Prune, 3: Remove
	action         int
	wantReferrers  []client.ObjectKey
	wantPruneCount int
	wantOk         bool
}

type resourceRefTestCase struct {
	m     refCacheMap
	name  string
	kind  ResourceKind
	tests []resourceRefTest
	want  refCacheMap
}

func Test_resourceReferenceCache(t *testing.T) {
	t.Parallel()
	referrer1 := client.ObjectKey{
		Namespace: "quz",
		Name:      "buz",
	}
	referrer2 := client.ObjectKey{
		Namespace: "qux",
		Name:      "buz",
	}
	reference1 := client.ObjectKey{
		Namespace: "baz",
		Name:      "buz",
	}
	reference2 := client.ObjectKey{
		Namespace: "baz",
		Name:      "qux",
	}

	tests := []resourceRefTestCase{
		{
			name: "set",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:     0,
					referrer:   referrer1,
					references: []client.ObjectKey{reference1},
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
					},
				},
			},
		},
		{
			name: "set-empty",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:   0,
					referrer: referrer1,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
					},
				},
			},
			want: refCacheMap{},
		},
		{
			name: "get",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:    1,
					reference: reference1,
					wantReferrers: []client.ObjectKey{
						referrer1,
						referrer2,
					},
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
		},
		{
			name: "get-none",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:    1,
					reference: reference1,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
		},
		{
			name: "prune",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					// prune
					action:         2,
					reference:      reference1,
					wantPruneCount: 1,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
		},
		{
			name: "prune-absent",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					// prune
					action:         2,
					reference:      reference1,
					wantPruneCount: 0,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference2: {},
					},
				},
			},
		},
		{
			name: "prune-empty",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					// prune
					action:         2,
					reference:      reference2,
					wantPruneCount: 2,
				},
				{
					// prune
					action:         2,
					reference:      reference1,
					wantPruneCount: 2,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
			want: refCacheMap{},
		},
		{
			name: "remove",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:   3,
					wantOk:   true,
					referrer: referrer1,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
			want: refCacheMap{
				SecretTransformation: {
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
		},
		{
			name: "remove-empty",
			kind: SecretTransformation,
			tests: []resourceRefTest{
				{
					action:   3,
					wantOk:   true,
					referrer: referrer1,
				},
				{
					action:   3,
					wantOk:   true,
					referrer: referrer2,
				},
			},
			m: refCacheMap{
				SecretTransformation: {
					referrer1: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
					referrer2: map[client.ObjectKey]empty{
						reference1: {},
						reference2: {},
					},
				},
			},
			want: refCacheMap{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &resourceReferenceCache{
				m: tt.m,
			}

			numTests := len(tt.tests)
			require.Greater(t, numTests, 0, "no test referrers provided")

			var wg sync.WaitGroup
			wg.Add(numTests)
			for _, test := range tt.tests {
				go func(test resourceRefTest) {
					c := c
					tt := tt
					defer wg.Done()

					switch test.action {
					case 0:
						// set
						c.Set(tt.kind, test.referrer, test.references...)
					case 1:
						// get
						actual := c.Get(tt.kind, test.reference)
						assert.ElementsMatchf(t, test.wantReferrers, actual,
							"Get(%v, %v)", tt.kind, test.reference)
					case 2:
						// prune
						assert.Equalf(t, test.wantPruneCount, c.Prune(tt.kind, test.reference),
							"Prune(%v, %v)", tt.kind, test.reference)
					case 3:
						// remove
						assert.Equalf(t, test.wantOk, c.Remove(tt.kind, test.referrer),
							"Remove(%v, %v)", tt.kind, test.referrer)
					default:
						require.Fail(t, "unsupported test action %v", test.action)
					}
				}(test)
			}

			wg.Wait()
			assert.Equalf(t, tt.want, c.m, "tests=%#v", tt.tests)
		})
	}
}

func TestSyncRegistry(t *testing.T) {
	t.Parallel()

	objKey1 := client.ObjectKey{
		Namespace: "foo",
		Name:      "qux",
	}
	objKey2 := client.ObjectKey{
		Namespace: "foo",
		Name:      "bar",
	}
	objKey3 := client.ObjectKey{
		Namespace: "baz",
		Name:      "qux",
	}
	type objKeyTest struct {
		objKey client.ObjectKey
		// action 0: Add, 1: Delete, 2: Has
		action  int
		wantHas bool
	}
	tests := []struct {
		name        string
		objKeyTests []objKeyTest
		m           map[client.ObjectKey]empty
		want        *SyncRegistry
	}{
		{
			name: "update",
			m:    map[client.ObjectKey]empty{},
			objKeyTests: []objKeyTest{
				{
					objKey: objKey1,
					action: 0,
				},
				{
					objKey: objKey1,
					action: 0,
				},
				{
					objKey: objKey1,
					action: 0,
				},
			},
			want: &SyncRegistry{
				m: map[client.ObjectKey]empty{
					objKey1: {},
				},
			},
		},
		{
			name: "delete",
			m: map[client.ObjectKey]empty{
				objKey1: {},
				objKey2: {},
			},
			objKeyTests: []objKeyTest{
				{
					objKey:  objKey1,
					action:  1,
					wantHas: true,
				},
				{
					objKey:  objKey2,
					action:  1,
					wantHas: true,
				},
				{
					objKey:  objKey3,
					action:  1,
					wantHas: false,
				},
			},
			want: &SyncRegistry{
				m: map[client.ObjectKey]empty{},
			},
		},
		{
			name: "has",
			m: map[client.ObjectKey]empty{
				objKey1: {},
			},
			objKeyTests: []objKeyTest{
				{
					objKey:  objKey1,
					action:  2,
					wantHas: true,
				},
				{
					objKey: objKey2,
					action: 2,
				},
			},
			want: &SyncRegistry{
				m: map[client.ObjectKey]empty{
					objKey1: {},
				},
			},
		},
		{
			name: "all-actions",
			m: map[client.ObjectKey]empty{
				objKey2: {},
			},
			objKeyTests: []objKeyTest{
				{
					objKey: objKey1,
					action: 0,
				},
				{
					objKey:  objKey2,
					action:  1,
					wantHas: true,
				},
				{
					objKey:  objKey2,
					action:  2,
					wantHas: true,
				},
			},
			want: &SyncRegistry{
				m: map[client.ObjectKey]empty{
					objKey1: {},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &SyncRegistry{
				m: tt.m,
			}

			var wg sync.WaitGroup
			wg.Add(len(tt.objKeyTests))
			for _, ttt := range tt.objKeyTests {
				go func(r *SyncRegistry, ttt objKeyTest) {
					defer wg.Done()
					switch ttt.action {
					case 0:
						r.Add(ttt.objKey)
					case 1:
						assert.Equal(t, ttt.wantHas, r.Delete(ttt.objKey))
					case 2:
						assert.Equal(t, ttt.wantHas, r.Has(ttt.objKey))
					default:
						assert.Fail(t, "invalid test action %d", ttt.action)
					}
				}(r, ttt)
			}
			wg.Wait()

			assert.Equal(t, tt.want, r)
		})
	}
}

func TestBackOffRegistry_Get(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		m      map[client.ObjectKey]*BackOff
		opts   []backoff.ExponentialBackOffOpts
		objKey client.ObjectKey
		want   bool
	}{
		{
			name: "new",
			m:    map[client.ObjectKey]*BackOff{},
			objKey: client.ObjectKey{
				Namespace: "foo",
				Name:      "bar",
			},
			opts: append(DefaultExponentialBackOffOpts(),
				backoff.WithRandomizationFactor(0.1)),
			want: true,
		},
		{
			name: "previous",
			m: map[client.ObjectKey]*BackOff{
				{
					Namespace: "foo",
					Name:      "bar",
				}: {
					bo: backoff.NewExponentialBackOff(
						backoff.WithRandomizationFactor(0.1),
					),
				},
			},
			objKey: client.ObjectKey{
				Namespace: "foo",
				Name:      "bar",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			r := &BackOffRegistry{
				m:    tt.m,
				opts: tt.opts,
			}
			bo, created := r.Get(tt.objKey)
			require.NotNilf(t, bo, "Get(%v)", tt.objKey)
			assert.Equalf(t, tt.want, created, "Get(%v)", tt.objKey)
			assert.Greaterf(t, bo.NextBackOff(), time.Duration(0), "Get(%v)", tt.objKey)

			bo, created = r.Get(tt.objKey)
			assert.False(t, created, "Get(%v)", tt.objKey)
			assert.Lessf(t, bo.NextBackOff(), bo.NextBackOff(), "Get(%v)", tt.objKey)
		})
	}
}

func TestBackOffRegistry_Delete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		m      map[client.ObjectKey]*BackOff
		opts   []backoff.ExponentialBackOffOpts
		objKey client.ObjectKey
		want   bool
	}{
		{
			name: "not-found",
			m:    map[client.ObjectKey]*BackOff{},
			objKey: client.ObjectKey{
				Namespace: "foo",
				Name:      "bar",
			},
			want: false,
		},
		{
			name: "deleted",
			m: map[client.ObjectKey]*BackOff{
				{
					Namespace: "foo",
					Name:      "bar",
				}: {
					bo: backoff.NewExponentialBackOff(
						DefaultExponentialBackOffOpts()...,
					),
				},
			},
			objKey: client.ObjectKey{
				Namespace: "foo",
				Name:      "bar",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &BackOffRegistry{
				m:    tt.m,
				opts: tt.opts,
			}
			got := r.Delete(tt.objKey)
			assert.Equalf(t, tt.want, got, "Delete(%v)", tt.objKey)
		})
	}
}
