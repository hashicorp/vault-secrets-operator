// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var refObjKey = client.ObjectKey{
	Namespace: "foo",
	Name:      "ref",
}

var referrer1 = client.ObjectKey{
	Namespace: "quz",
	Name:      "buz",
}

var referrer2 = client.ObjectKey{
	Namespace: "buz",
	Name:      "qux",
}

type resourceRefTestCase struct {
	m              map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty
	name           string
	kind           ResourceKind
	ref            client.ObjectKey
	referrers      []client.ObjectKey
	calls          int
	want           map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty
	wantOk         bool
	wantReferrers  []client.ObjectKey
	wantPruneCount int
}

func Test_resourceReferenceCache_Add(t *testing.T) {
	t.Parallel()

	tests := []resourceRefTestCase{
		{
			name: "single",
			kind: SecretTransformation,
			ref:  refObjKey,
			referrers: []client.ObjectKey{
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
					},
				},
			},
		},
		{
			name: "multi",
			kind: SecretTransformation,
			ref:  refObjKey,
			referrers: []client.ObjectKey{
				referrer2,
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
						referrer2: {},
					},
				},
			},
		},
		{
			name: "multi-dupes",
			kind: SecretTransformation,
			ref:  refObjKey,
			referrers: []client.ObjectKey{
				referrer2,
				referrer1,
				referrer2,
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
						referrer2: {},
					},
				},
			},
		},
		{
			name:  "multi-dupes-concurrent",
			kind:  SecretTransformation,
			ref:   refObjKey,
			calls: 10,
			referrers: []client.ObjectKey{
				referrer2,
				referrer1,
				referrer2,
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
						referrer2: {},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &resourceReferenceCache{
				m: tt.m,
			}

			// test cache locking
			if tt.calls > 0 {
				var wg sync.WaitGroup
				wg.Add(tt.calls)
				for i := 0; i < tt.calls; i++ {
					go func() {
						c := c
						tt := tt
						defer wg.Done()
						c.Add(tt.kind, tt.ref, tt.referrers...)
					}()
				}
				wg.Wait()
			} else {
				c.Add(tt.kind, tt.ref, tt.referrers...)
			}
			assert.Equalf(t, tt.want, c.m, "Add(%v, %v)", tt.ref, tt.referrers)
		})
	}
}

func Test_resourceReferenceCache_PruneReferrer(t *testing.T) {
	t.Parallel()

	tests := []resourceRefTestCase{
		{
			name:           "last",
			kind:           SecretTransformation,
			ref:            referrer1,
			wantPruneCount: 1,
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
					},
				},
			},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
		},
		{
			name:           "ok",
			kind:           SecretTransformation,
			ref:            referrer1,
			wantPruneCount: 1,
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
						referrer2: {},
					},
				},
			},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer2: {},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &resourceReferenceCache{
				m: tt.m,
			}

			assert.Equalf(t, tt.wantPruneCount, c.Prune(tt.kind, tt.ref), "Prune(%v, %v)", tt.kind, tt.ref)
			assert.Equalf(t, tt.want, c.m, "Prune(%v, %v)", tt.kind, tt.ref)
		})
	}
}

func Test_resourceReferenceCache_Get(t *testing.T) {
	t.Parallel()

	tests := []resourceRefTestCase{
		{
			name: "empty",
			kind: SecretTransformation,
			ref:  referrer1,
			m:    map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
			want: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{},
		},
		{
			name:   "one",
			kind:   SecretTransformation,
			ref:    refObjKey,
			wantOk: true,
			wantReferrers: []client.ObjectKey{
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer1: {},
					},
				},
			},
		},
		{
			name:   "two",
			kind:   SecretTransformation,
			ref:    refObjKey,
			wantOk: true,
			wantReferrers: []client.ObjectKey{
				referrer2,
				referrer1,
			},
			m: map[ResourceKind]map[client.ObjectKey]map[client.ObjectKey]empty{
				SecretTransformation: {
					refObjKey: map[client.ObjectKey]empty{
						referrer2: {},
						referrer1: {},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &resourceReferenceCache{
				m: tt.m,
			}

			t.Logf("%v", c.m)

			if tt.calls > 0 {
				var wg sync.WaitGroup
				wg.Add(tt.calls)
				for i := 0; i < tt.calls; i++ {
					go func() {
						c := c
						tt := tt
						defer wg.Done()
						got1, got := c.Get(tt.kind, tt.ref)
						assert.Equalf(t, tt.wantOk, got, "Get(%v, %v)", tt.kind, tt.ref)
						assert.ElementsMatchf(t, tt.wantReferrers, got1, "Get(%v, %v)", tt.kind, tt.ref)
					}()
				}
				wg.Wait()
			} else {
				c.Add(tt.kind, tt.ref, tt.referrers...)
				got1, got := c.Get(tt.kind, tt.ref)
				assert.Equalf(t, tt.wantOk, got, "Get(%v, %v)", tt.kind, tt.ref)
				assert.ElementsMatchf(t, tt.wantReferrers, got1, "Get(%v, %v)", tt.kind, tt.ref)
			}
		})
	}
}
