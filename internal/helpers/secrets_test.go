// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

func TestFindSecretsOwnedByObj(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme)
	defaultClient := clientBuilder.Build()

	owner := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "VaultDynamicSecret",
			APIVersion: "secrets.hashicorp.com/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "baz",
			Namespace:  "foo",
			Generation: 1,
			UID:        types.UID("buzz"),
		},
	}

	ownerLabels := make(map[string]string)
	for k, v := range OwnerLabels {
		ownerLabels[k] = v
	}
	ownerLabels[labelOwnerRefUID] = string(owner.GetUID())

	notOwner := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "VaultDynamicSecret",
			APIVersion: "secrets.hashicorp.com/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "qux",
			Namespace:  "foo",
			Generation: 1,
			UID:        types.UID("biff"),
		},
	}

	ownedSec1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ownedSec1",
			Namespace: owner.Namespace,
			Labels:    ownerLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: owner.APIVersion,
					Kind:       owner.Kind,
					Name:       owner.Name,
					UID:        owner.GetUID(),
				},
			},
		},
	}
	require.NoError(t, defaultClient.Create(ctx, ownedSec1))

	ownedSec2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ownedSec2",
			Namespace: owner.Namespace,
			Labels:    ownerLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: owner.APIVersion,
					Kind:       owner.Kind,
					Name:       owner.Name,
					UID:        owner.GetUID(),
				},
			},
		},
	}
	require.NoError(t, defaultClient.Create(ctx, ownedSec2))

	// is owned by owner but does not have matching labels
	canarySec1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "canarySec1",
			Namespace: owner.Namespace,
			Labels:    OwnerLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: owner.APIVersion,
					Kind:       owner.Kind,
					Name:       owner.Name,
					UID:        owner.GetUID(),
				},
			},
		},
	}
	require.NoError(t, defaultClient.Create(ctx, canarySec1))

	// has matching labels but is not owned by owner
	canarySec2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "canarySec2",
			Namespace: notOwner.Namespace,
			Labels:    ownerLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: notOwner.APIVersion,
					Kind:       notOwner.Kind,
					Name:       notOwner.Name,
					UID:        notOwner.GetUID(),
				},
			},
		},
	}
	require.NoError(t, defaultClient.Create(ctx, canarySec2))

	tests := []struct {
		name        string
		owner       ctrlclient.Object
		createOwned int
		want        []corev1.Secret
		wantErr     assert.ErrorAssertionFunc
	}{
		{
			name:    "find-some",
			owner:   owner,
			want:    []corev1.Secret{*ownedSec1, *ownedSec2},
			wantErr: assert.NoError,
		},
		{
			name:    "find-none",
			owner:   notOwner,
			want:    nil,
			wantErr: assert.NoError,
		},
		{
			name: "error-invalid-owner-object",
			owner: &metav1.PartialObjectMetadata{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t,
					err, runtime.NewMissingKindErr("unstructured object has no kind").Error(), i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FindSecretsOwnedByObj(ctx, defaultClient, tt.owner)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"FindSecretsOwnedByObj(%v, %v, %v)", ctx, defaultClient, tt.owner)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"FindSecretsOwnedByObj(%v, %v, %v)", ctx, defaultClient, tt.owner)
		})
	}
}

func TestSyncSecret(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(secretsv1beta1.AddToScheme(scheme))
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme)

	defaultOwner := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "VaultDynamicSecret",
			APIVersion: "secrets.hashicorp.com/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "baz",
			Namespace:  "foo",
			Generation: 1,
			UID:        types.UID("buzz"),
		},
	}

	ownerWithDest := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta:   defaultOwner.TypeMeta,
		ObjectMeta: defaultOwner.ObjectMeta,
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Destination: secretsv1beta1.Destination{
				Name:   "baz",
				Create: true,
			},
		},
	}

	ownerWithDestNoCreate := &secretsv1beta1.VaultDynamicSecret{}
	ownerWithDest.DeepCopyInto(ownerWithDestNoCreate)
	ownerWithDestNoCreate.Spec.Destination.Create = false

	invalidNoDest := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta:   defaultOwner.TypeMeta,
		ObjectMeta: defaultOwner.ObjectMeta,
	}

	invalidEmptyDestName := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta:   defaultOwner.TypeMeta,
		ObjectMeta: defaultOwner.ObjectMeta,
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Destination: secretsv1beta1.Destination{
				Create: true,
			},
		},
	}

	invalidEmptyNamespace := &secretsv1beta1.VaultDynamicSecret{
		TypeMeta:   defaultOwner.TypeMeta,
		ObjectMeta: defaultOwner.ObjectMeta,
		Spec: secretsv1beta1.VaultDynamicSecretSpec{
			Destination: secretsv1beta1.Destination{
				Name: "baz",
			},
		},
	}
	invalidEmptyNamespace.Namespace = ""

	defaultOpts := []SyncOptions{DefaultSyncOptions()}

	tests := []struct {
		name   string
		client ctrlclient.Client
		// this could be any syncable secret type VSS, VPS, etc.
		obj                *secretsv1beta1.VaultDynamicSecret
		data               map[string][]byte
		orphans            int
		createDest         bool
		expectSecretsCount int
		opts               []SyncOptions
		wantErr            assert.ErrorAssertionFunc
	}{
		{
			name:   "invalid-no-dest",
			client: clientBuilder.Build(),
			obj:    invalidNoDest,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyError)
			},
		},
		{
			name:   "invalid-dest-name-empty",
			client: clientBuilder.Build(),
			obj:    invalidEmptyDestName,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyErrorEmptyName)
			},
		},
		{
			name:   "invalid-namespace-empty",
			client: clientBuilder.Build(),
			obj:    invalidEmptyNamespace,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyErrorEmptyNamespace)
			},
		},
		{
			name:   "valid-dest",
			client: clientBuilder.Build(),
			obj:    ownerWithDest,
			data: map[string][]byte{
				"foo": []byte(`baz`),
			},
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-default-opts",
			client:  clientBuilder.Build(),
			orphans: 5,
			opts:    defaultOpts,
			obj:     ownerWithDest,
			data: map[string][]byte{
				"qux": []byte(`bar`),
			},
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-prune-orphans",
			client:  clientBuilder.Build(),
			orphans: 5,
			opts: []SyncOptions{
				{
					PruneOrphans: true,
				},
			},
			obj:                ownerWithDest,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-no-prune-orphans",
			client:  clientBuilder.Build(),
			orphans: 5,
			opts: []SyncOptions{
				{
					PruneOrphans: false,
				},
			},
			data: map[string][]byte{
				"biff": []byte(`baz`),
			},
			obj:                ownerWithDest,
			expectSecretsCount: 6,
			wantErr:            assert.NoError,
		},
		{
			name:   "invalid-dest-inexistent-create-false",
			client: clientBuilder.Build(),
			obj:    ownerWithDestNoCreate,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"destination secret foo/baz does not exist, and create=false")
			},
		},
		{
			name:   "valid-dest-exists-create-false",
			client: clientBuilder.Build(),
			obj:    ownerWithDestNoCreate,
			data: map[string][]byte{
				"bar": []byte(`foo`),
			},
			createDest:         true,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-exists-create-false-orphans",
			client:  clientBuilder.Build(),
			orphans: 5,
			obj:     ownerWithDestNoCreate,
			data: map[string][]byte{
				"bar": []byte(`qux`),
			},
			createDest:         true,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-exists-create-false-no-prune-orphans",
			client:  clientBuilder.Build(),
			orphans: 5,
			opts: []SyncOptions{
				{
					PruneOrphans: false,
				},
			},
			obj: ownerWithDestNoCreate,
			data: map[string][]byte{
				"bar": []byte(`qux`),
			},
			createDest:         true,
			expectSecretsCount: 6,
			wantErr:            assert.NoError,
		},
		{
			name:               "invalid-dest-exists-create-true",
			client:             clientBuilder.Build(),
			obj:                ownerWithDest,
			createDest:         true,
			expectSecretsCount: 1,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					"not the owner of the destination Secret foo/baz")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// create the destination secret
			if tt.createDest {
				require.NotEmpty(t, tt.obj.Spec.Destination.Name,
					"test object must Spec.Destination.Name set")
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.obj.Spec.Destination.Name,
						Namespace: tt.obj.GetNamespace(),
					},
				}
				require.NoError(t, tt.client.Create(ctx, s))
			}

			ownerLabels := make(map[string]string)
			for k, v := range OwnerLabels {
				ownerLabels[k] = v
			}

			if tt.obj.GetUID() != "" {
				ownerLabels[labelOwnerRefUID] = string(tt.obj.GetUID())
			}

			var orphans []ctrlclient.ObjectKey
			// create some orphans that are owned by tt.obj
			for i := 0; i < tt.orphans; i++ {
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("orphan-%d", i),
						Namespace: tt.obj.GetNamespace(),
						Labels:    ownerLabels,
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: tt.obj.APIVersion,
								Kind:       tt.obj.Kind,
								Name:       tt.obj.Name,
								UID:        tt.obj.GetUID(),
							},
						},
					},
				}
				require.NoError(t, tt.client.Create(ctx, s))
				orphans = append(orphans, ctrlclient.ObjectKeyFromObject(s))
			}

			var expectOpts SyncOptions
			if len(tt.opts) == 0 {
				expectOpts = defaultOpts[0]
			} else {
				expectOpts = tt.opts[0]
			}

			syncErr := SyncSecret(ctx, tt.client, tt.obj, tt.data, tt.opts...)
			tt.wantErr(t, syncErr,
				fmt.Sprintf("SyncSecret(%v, %v, %v, %v, %v)", ctx, tt.client, tt.obj, tt.data, tt.opts))

			destSecObjKey := ctrlclient.ObjectKey{
				Namespace: tt.obj.Namespace,
				Name:      tt.obj.Spec.Destination.Name,
			}

			var destSecret corev1.Secret
			destGetErr := tt.client.Get(ctx, destSecObjKey, &destSecret)
			if syncErr != nil {
				if !tt.createDest {
					assert.True(t, apierrors.IsNotFound(destGetErr))
				}
			} else {
				assert.Equal(t, tt.data, destSecret.Data)
			}

			for _, objKey := range orphans {
				var s corev1.Secret
				orphanGetErr := tt.client.Get(ctx, objKey, &s)
				if syncErr != nil || !expectOpts.PruneOrphans {
					// ensure orphan was left unharmed
					assert.NoError(t, orphanGetErr)
				} else {
					// ensure orphan was deleted
					assert.True(t, apierrors.IsNotFound(orphanGetErr))
				}
			}

			secrets := &corev1.SecretList{}
			if assert.NoError(t, tt.client.List(ctx, secrets,
				ctrlclient.InNamespace(tt.obj.GetNamespace()))) {
				assert.Equal(t, tt.expectSecretsCount, len(secrets.Items))
			}
		})
	}
}
