// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-11-28/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/internal/testutils"
)

func TestFindSecretsOwnedByObj(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	defaultClient := testutils.NewFakeClient()

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
			tt := tt
			t.Parallel()

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
	// t.Parallel()

	ctx := context.Background()

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

	ownerWithCreateAndType := &secretsv1beta1.VaultDynamicSecret{}
	ownerWithDest.DeepCopyInto(ownerWithCreateAndType)
	ownerWithCreateAndType.Spec.Destination.Type = corev1.SecretTypeDockercfg

	ownerWithDestNoCreate := &secretsv1beta1.VaultDynamicSecret{}
	ownerWithDest.DeepCopyInto(ownerWithDestNoCreate)
	ownerWithDestNoCreate.Spec.Destination.Create = false

	ownerWithDestNoCreateOverwrite := &secretsv1beta1.VaultDynamicSecret{}
	ownerWithDest.DeepCopyInto(ownerWithDestNoCreateOverwrite)
	ownerWithDestNoCreateOverwrite.Spec.Destination.Create = false
	ownerWithDestNoCreateOverwrite.Spec.Destination.Overwrite = true

	ownerWithDestOverwrite := &secretsv1beta1.VaultDynamicSecret{}
	ownerWithDest.DeepCopyInto(ownerWithDestOverwrite)
	ownerWithDestOverwrite.Spec.Destination.Overwrite = true

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
		obj                 *secretsv1beta1.VaultDynamicSecret
		data                map[string][]byte
		orphans             int
		createDest          bool
		destLabels          map[string]string
		destOwnerReferences []metav1.OwnerReference
		expectSecretsCount  int
		opts                []SyncOptions
		wantErr             assert.ErrorAssertionFunc
	}{
		{
			name:   "invalid-no-dest",
			client: testutils.NewFakeClient(),
			obj:    invalidNoDest,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyError)
			},
		},
		{
			name:   "invalid-dest-name-empty",
			client: testutils.NewFakeClient(),
			obj:    invalidEmptyDestName,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyErrorEmptyName)
			},
		},
		{
			name:   "invalid-namespace-empty",
			client: testutils.NewFakeClient(),
			obj:    invalidEmptyNamespace,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, common.InvalidObjectKeyErrorEmptyNamespace)
			},
		},
		{
			name:   "valid-dest",
			client: testutils.NewFakeClient(),
			obj:    ownerWithDest,
			data: map[string][]byte{
				"foo": []byte(`baz`),
			},
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-default-opts",
			client:  testutils.NewFakeClient(),
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
			name:   "valid-dest-prune-orphans",
			client: testutils.NewFakeClient(),
			opts: []SyncOptions{
				{
					PruneOrphans: true,
				},
			},
			obj:        ownerWithCreateAndType,
			destLabels: maps.Clone(OwnerLabels),
			destOwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: ownerWithCreateAndType.APIVersion,
					Kind:       ownerWithCreateAndType.Kind,
					Name:       ownerWithCreateAndType.Name,
					UID:        ownerWithCreateAndType.UID,
				},
			},
			createDest:         true,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:    "valid-dest-prune-orphans",
			client:  testutils.NewFakeClient(),
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
			client:  testutils.NewFakeClient(),
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
			client: testutils.NewFakeClient(),
			obj:    ownerWithDestNoCreate,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"destination secret foo/baz does not exist, and create=false")
			},
		},
		{
			name:   "valid-dest-exists-create-false",
			client: testutils.NewFakeClient(),
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
			client:  testutils.NewFakeClient(),
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
			client:  testutils.NewFakeClient(),
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
			client:             testutils.NewFakeClient(),
			obj:                ownerWithDest,
			createDest:         true,
			expectSecretsCount: 1,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					"not the owner of the destination Secret foo/baz")
			},
		},
		{
			name:               "invalid-dest-exists-no-create-overwrite",
			client:             testutils.NewFakeClient(),
			obj:                ownerWithDestNoCreateOverwrite,
			createDest:         false,
			expectSecretsCount: 0,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"destination secret foo/baz does not exist, and create=false")
			},
		},
		{
			name:               "dest-exists-not-owned-overwrite-true",
			client:             testutils.NewFakeClient(),
			obj:                ownerWithDestOverwrite,
			createDest:         true,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:               "dest-exists-owned-overwrite-true",
			client:             testutils.NewFakeClient(),
			obj:                ownerWithDestOverwrite,
			createDest:         true,
			destLabels:         OwnerLabels,
			expectSecretsCount: 1,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					"not the owner of the destination Secret foo/baz")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			// create the destination secret
			if tt.createDest {
				require.NotEmpty(t, tt.obj.Spec.Destination.Name,
					"test object must Spec.Destination.Name set")
				s := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:            tt.obj.Spec.Destination.Name,
						Namespace:       tt.obj.GetNamespace(),
						Labels:          tt.destLabels,
						OwnerReferences: tt.destOwnerReferences,
					},
					Type: corev1.SecretTypeOpaque,
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
								Controller: ptr.To(true),
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
				wantType := tt.obj.Spec.Destination.Type
				if wantType == "" {
					wantType = corev1.SecretTypeOpaque
				}
				assert.Equal(t, wantType, destSecret.Type)
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

func TestSecretDataBuilder_WithVaultData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    map[string]interface{}
		opt     *SecretTransformationOption
		raw     map[string]interface{}
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "equal-raw-data",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				"baz": []byte(`qux`),
				"foo": []byte(`biff`),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "mixed",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"foo":  "bar",
				"biff": "buz",
				"buz":  1,
			},
			want: map[string][]byte{
				"baz": []byte(`qux`),
				"foo": []byte(`biff`),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"biff": "buz",
					"foo":  "bar",
					"buz":  1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name:    "nil-data-nil-raw",
			data:    nil,
			raw:     nil,
			want:    map[string][]byte{SecretDataKeyRaw: []byte(`null`)},
			wantErr: assert.NoError,
		},
		{
			name: "nil-data",
			data: nil,
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "nil-raw",
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: nil,
			want: map[string][]byte{
				SecretDataKeyRaw: []byte(`null`),
				"baz":            []byte("qux"),
				"foo":            []byte("biff"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-raw-data-unmarshalable",
			data: nil,
			raw: map[string]interface{}{
				"baz": make(chan int),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name: "invalid-data-unmarshalable",
			data: map[string]interface{}{
				"baz": make(chan int),
			},
			raw:  nil,
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "json: unsupported type: chan int")
			},
		},
		{
			name: "invalid-data-contains-raw",
			data: map[string]interface{}{
				SecretDataKeyRaw: "qux",
				"baz":            "foo",
			},
			raw: map[string]interface{}{
				"baz": "foo",
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, SecretDataErrorContainsRaw)
			},
		},
		{
			name: "tmpl-equal-raw-data",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }} {{- printf "%s=%s\n" $key $value -}}
{{- end }}`,
						},
					},
					{
						Key: "qux",
						Template: secretsv1beta1.Template{
							Name: "tmpl2",
							Text: `it`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				"buz": []byte("baz=qux\nfoo=biff\n"),
				"qux": []byte("it"),
				"baz": []byte("qux"),
				"foo": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},

			wantErr: assert.NoError,
		},
		{
			name: "tmpl-b64enc-values",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%s\n" $key ( $value | b64enc ) -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
			},
			want: map[string][]byte{
				"buz": []byte(fmt.Sprintf(
					"baz=%s\nfoo=%s\n",
					base64.StdEncoding.EncodeToString([]byte(`qux`)),
					base64.StdEncoding.EncodeToString([]byte(`biff`)),
				)),
				"baz": []byte("qux"),
				"foo": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
				}),
			},

			wantErr: assert.NoError,
		},
		{
			name: "tmpl-b64dec-values",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%s\n" $key ( $value | b64dec ) -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
				"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
			},
			raw: map[string]interface{}{
				"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
				"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
			},
			want: map[string][]byte{
				"buz": []byte(fmt.Sprintf(
					"baz=%s\nfoo=%s\n", `qux`, `biff`),
				),
				"baz": []byte(base64.StdEncoding.EncodeToString([]byte(`qux`))),
				"foo": []byte(base64.StdEncoding.EncodeToString([]byte(`biff`))),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
					"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
				}),
			},

			wantErr: assert.NoError,
		},
		{
			name: "tmpl-with-metadata",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets -}}
{{- printf "SEC_%s=%s\n" ( $key | upper ) ( $value | b64dec ) -}}
{{- end }}
{{- range $key, $value := get .Metadata "custom_metadata" -}}
{{- printf "META_%s=%s\n" ( $key | upper ) $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
				"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
			},
			raw: map[string]interface{}{
				"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
				"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
				"metadata": map[string]any{
					"custom_metadata": map[string]any{
						"qux": "biff",
					},
				},
			},
			want: map[string][]byte{
				"buz": []byte(`SEC_BAZ=qux
SEC_FOO=biff
META_QUX=biff
`,
				),
				"baz": []byte(base64.StdEncoding.EncodeToString([]byte(`qux`))),
				"foo": []byte(base64.StdEncoding.EncodeToString([]byte(`biff`))),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": base64.StdEncoding.EncodeToString([]byte(`qux`)),
					"foo": base64.StdEncoding.EncodeToString([]byte(`biff`)),
					"metadata": map[string]any{
						"custom_metadata": map[string]any{
							"qux": "biff",
						},
					},
				}),
			},

			wantErr: assert.NoError,
		},
		{
			name: "tmpl-mixed",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%v\n" $key $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"buz": []byte("baz=qux\nbuz=1\nfoo=biff\n"),
				"foo": []byte("biff"),
				"baz": []byte("qux"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-filter-includes-mixed",
			opt: &SecretTransformationOption{
				Includes: []string{`^buz$`},
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%v\n" $key $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"buz": []byte("baz=qux\nbuz=1\nfoo=biff\n"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-filter-subset-includes-mixed",
			opt: &SecretTransformationOption{
				Includes: []string{`^foo$`},
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%v\n" $key $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"buz": []byte("baz=qux\nbuz=1\nfoo=biff\n"),
				"foo": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-render-range-over-error",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := . }}
{{- printf "%s=%v\n" $key $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
			},
			raw: map[string]interface{}{
				"baz": "qux",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template: tmpl1:1:26: executing "tmpl1" at <.>: `+
						`range can't iterate over <redacted>`,
				)
			},
		},
		{
			name: "tmpl-render-function-not-defined-error",
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%v\n" $key ($value | bx2dec -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
			},
			raw: map[string]interface{}{
				"baz": "qux",
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`parse error: template: tmpl1:2: function "bx2dec" not defined`,
				)
			},
		},
		{
			name: "tmpl-filtered-excludes-mixed",
			opt: &SecretTransformationOption{
				// buz should not be excluded since it is a rendered template field.
				Excludes: []string{
					`^buz$'`,
					`^baz$`,
					`^foo$`,
				},
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "buz",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- range $key, $value := .Secrets }}
{{- printf "%s=%v\n" $key $value -}}
{{- end }}`,
						},
					},
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"buz": []byte("baz=qux\nbuz=1\nfoo=biff\n"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-exclude-all",
			opt: &SecretTransformationOption{
				Excludes: []string{
					`^(buz|baz|foo)$`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-include",
			opt: &SecretTransformationOption{
				Includes: []string{
					`^foo$`,
					`^baz$`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"baz": []byte("qux"),
				"foo": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-both-mutually-exclusive",
			opt: &SecretTransformationOption{
				Includes: []string{
					`^(baz|foo)$`,
				},
				Excludes: []string{
					`^foo$`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"foo": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"baz": []byte("qux"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"foo": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-include-greedy",
			opt: &SecretTransformationOption{
				Includes: []string{
					`.*b.*`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"baz": []byte("qux"),
				"buz": marshalRaw(t, 1),
				"fab": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"fab": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-both-greedy",
			opt: &SecretTransformationOption{
				Includes: []string{
					`.*b.*`,
				},
				Excludes: []string{
					`.*z.*`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"fab": []byte("biff"),
				SecretDataKeyRaw: marshalRaw(t, map[string]any{
					"baz": "qux",
					"fab": "biff",
					"buz": 1,
				}),
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-both-greedy-exclude-raw",
			opt: &SecretTransformationOption{
				ExcludeRaw: true,
				Includes: []string{
					`.*b.*`,
				},
				Excludes: []string{
					`.*z.*`,
				},
			},
			data: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
				"buz": 1,
			},
			want: map[string][]byte{
				"fab": []byte("biff"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "exclude-raw",
			opt: &SecretTransformationOption{
				ExcludeRaw: true,
			},
			data: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
			},
			raw: map[string]interface{}{
				"baz": "qux",
				"fab": "biff",
			},
			want: map[string][]byte{
				"baz": []byte("qux"),
				"fab": []byte("biff"),
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			s := &SecretDataBuilder{}
			got, err := s.WithVaultData(tt.data, tt.raw, tt.opt)
			if !tt.wantErr(t, err, fmt.Sprintf("WithVaultData(%v, %v)", tt.data, tt.raw)) {
				return
			}
			assert.Equalf(t, tt.want, got, "WithVaultData(%v, %v)", tt.data, tt.raw)
		})
	}
}

func TestSecretDataBuilder_WithHVSAppSecrets(t *testing.T) {
	t.Parallel()

	respValid := &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20231128OpenAppSecretsResponse{
			Secrets: []*models.Secrets20231128OpenSecret{
				{
					CreatedAt:     strfmt.NewDateTime(),
					CreatedByID:   "vso uuid",
					LatestVersion: 1,
					Name:          "bar",
					SyncStatus:    nil,
					StaticVersion: &models.Secrets20231128OpenSecretStaticVersion{
						CreatedAt:   strfmt.DateTime{},
						CreatedByID: "vso uuid",
						Value:       "foo",
						Version:     1,
					},
					Type: HVSSecretTypeKV,
				},
				{
					CreatedAt:     strfmt.NewDateTime(),
					CreatedByID:   "vso-1 uuid",
					LatestVersion: 2,
					Name:          "foo",
					SyncStatus:    nil,
					StaticVersion: &models.Secrets20231128OpenSecretStaticVersion{
						CreatedAt:   strfmt.DateTime{},
						CreatedByID: "vso-1 uuid",
						Value:       "qux",
						Version:     2,
					},
					Type: HVSSecretTypeKV,
				},
				{
					CreatedAt:     strfmt.NewDateTime(),
					CreatedByID:   "vso-2 uuid",
					LatestVersion: 1,
					Name:          "rotatingfoo",
					Provider:      "providerfoo",
					SyncStatus:    nil,
					RotatingVersion: &models.Secrets20231128OpenSecretRotatingVersion{
						CreatedAt:   strfmt.DateTime{},
						CreatedByID: "vault-secrets-rotator",
						ExpiresAt:   strfmt.DateTime{},
						Keys: []string{
							"api_key_one",
							"api_key_two",
						},
						Values: map[string]string{
							"api_key_one": "123456",
							"api_key_two": "654321",
						},
						Version: 1,
					},
					Type: HVSSecretTypeRotating,
				},
				{
					CreatedAt:     strfmt.NewDateTime(),
					CreatedByID:   "vso-3 uuid",
					LatestVersion: 1,
					Name:          "dyn",
					Provider:      "providerfoo",
					SyncStatus:    nil,
					DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
						TTL:       "1h",
						CreatedAt: strfmt.DateTime{},
						ExpiresAt: strfmt.DateTime{},
						Values: map[string]string{
							"val_one": "123456",
							"val_two": "654321",
						},
					},
					Type: HVSSecretTypeDynamic,
				},
			},
		},
	}

	rawValid, err := respValid.GetPayload().MarshalBinary()
	require.NoError(t, err)

	rotatingValueRaw, err := marshalJSON(map[string]string{
		"api_key_one": "123456",
		"api_key_two": "654321",
	})
	require.NoError(t, err)

	dynValueRaw, err := marshalJSON(map[string]string{
		"val_one": "123456",
		"val_two": "654321",
	})

	respValidUnsupportedType := &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20231128OpenAppSecretsResponse{
			Secrets: []*models.Secrets20231128OpenSecret{
				{
					Name: "biff",
					Type: HVSSecretTypeKV,
					StaticVersion: &models.Secrets20231128OpenSecretStaticVersion{
						CreatedAt:   strfmt.DateTime{},
						CreatedByID: "",
						Value:       "baz",
					},
				},
				{
					Name: "baz",
					Type: "_unsupported_",
				},
			},
		},
	}

	rawUnsupportedType, err := respValidUnsupportedType.GetPayload().MarshalBinary()
	require.NoError(t, err)

	respContainsRaw := &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20231128OpenAppSecretsResponse{
			Secrets: []*models.Secrets20231128OpenSecret{
				{
					CreatedAt:     strfmt.DateTime{},
					CreatedByID:   "",
					LatestVersion: 1,
					Name:          SecretDataKeyRaw,
					SyncStatus:    nil,
					StaticVersion: &models.Secrets20231128OpenSecretStaticVersion{
						CreatedAt:   strfmt.DateTime{},
						CreatedByID: "",
						Value:       "foo",
						Version:     1,
					},
					Type: HVSSecretTypeKV,
				},
			},
		},
	}

	tests := []struct {
		name    string
		resp    *hvsclient.OpenAppSecretsOK
		opt     *SecretTransformationOption
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			resp: respValid,
			want: map[string][]byte{
				"bar":                     []byte("foo"),
				"foo":                     []byte("qux"),
				"rotatingfoo_api_key_one": []byte("123456"),
				"rotatingfoo_api_key_two": []byte("654321"),
				"rotatingfoo":             rotatingValueRaw,
				"dyn":                     dynValueRaw,
				"dyn_val_one":             []byte("123456"),
				"dyn_val_two":             []byte("654321"),
				SecretDataKeyRaw:          rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-valid",
			resp: respValid,
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "bar",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- get .Secrets "bar" | upper -}}`,
						},
					},
				},
			},
			want: map[string][]byte{
				"bar":                     []byte("FOO"),
				"foo":                     []byte("qux"),
				"rotatingfoo_api_key_one": []byte("123456"),
				"rotatingfoo_api_key_two": []byte("654321"),
				"rotatingfoo":             rotatingValueRaw,
				"dyn":                     dynValueRaw,
				"dyn_val_one":             []byte("123456"),
				"dyn_val_two":             []byte("654321"),
				SecretDataKeyRaw:          rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-with-metadata-valid",
			resp: respValid,
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "metadata.json",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- .Metadata | mustToPrettyJson -}}`,
						},
					},
					{
						Key: "dyn_ttl",
						Template: secretsv1beta1.Template{
							Name: "tmpl2",
							Text: `{{- get (get (get .Metadata "dyn") "dynamic_config") "ttl" -}}`,
						},
					},
				},
			},
			want: map[string][]byte{
				"metadata.json": []byte(`{
  "bar": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "latest_version": 1,
    "name": "bar",
    "static_version": {
      "created_at": "0001-01-01T00:00:00.000Z",
      "version": 1
    },
    "type": "kv"
  },
  "dyn": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "dynamic_config": {
      "ttl": "1h"
    },
    "latest_version": 1,
    "name": "dyn",
    "provider": "providerfoo",
    "type": "dynamic"
  },
  "foo": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "latest_version": 2,
    "name": "foo",
    "static_version": {
      "created_at": "0001-01-01T00:00:00.000Z",
      "version": 2
    },
    "type": "kv"
  },
  "rotatingfoo": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "latest_version": 1,
    "name": "rotatingfoo",
    "provider": "providerfoo",
    "rotating_version": {
      "created_at": "0001-01-01T00:00:00.000Z",
      "expires_at": "0001-01-01T00:00:00.000Z",
      "keys": [
        "api_key_one",
        "api_key_two"
      ],
      "revoked_at": "0001-01-01T00:00:00.000Z",
      "version": 1
    },
    "type": "rotating"
  }
}`,
				),
				"bar":                     []byte("foo"),
				"foo":                     []byte("qux"),
				"rotatingfoo_api_key_one": []byte("123456"),
				"rotatingfoo_api_key_two": []byte("654321"),
				"rotatingfoo":             rotatingValueRaw,
				"dyn":                     dynValueRaw,
				"dyn_val_one":             []byte("123456"),
				"dyn_val_two":             []byte("654321"),
				"dyn_ttl":                 []byte("1h"),
				SecretDataKeyRaw:          rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "tmpl-filter-excludes-valid",
			resp: respValid,
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "bar",
						Template: secretsv1beta1.Template{
							Name: "tmpl1",
							Text: `{{- get .Secrets "bar" | upper -}}`,
						},
					},
					{
						Key: "dyn_template_val_one",
						Template: secretsv1beta1.Template{
							Name: "tmpl2",
							Text: `{{- get (get .Secrets "dyn") "val_one" -}}`,
						},
					},
					{
						Key: "dyn_template_val_two",
						Template: secretsv1beta1.Template{
							Name: "tmpl3",
							Text: `{{- dig "dyn" "val_two" "<missing>" .Secrets -}}`,
						},
					},
				},
				Excludes: []string{"foo"},
			},
			want: map[string][]byte{
				"bar":                  []byte("FOO"),
				"dyn":                  dynValueRaw,
				"dyn_val_one":          []byte("123456"),
				"dyn_val_two":          []byte("654321"),
				"dyn_template_val_one": []byte("123456"),
				"dyn_template_val_two": []byte("654321"),
				SecretDataKeyRaw:       rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-includes-valid",
			resp: respValid,
			opt: &SecretTransformationOption{
				Includes: []string{"foo"},
			},
			want: map[string][]byte{
				"foo":                     []byte("qux"),
				"rotatingfoo_api_key_one": []byte("123456"),
				"rotatingfoo_api_key_two": []byte("654321"),
				"rotatingfoo":             rotatingValueRaw,
				SecretDataKeyRaw:          rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-excludes-valid",
			resp: respValid,
			opt: &SecretTransformationOption{
				Excludes: []string{"foo"},
			},
			want: map[string][]byte{
				"bar":            []byte("foo"),
				"dyn":            dynValueRaw,
				"dyn_val_one":    []byte("123456"),
				"dyn_val_two":    []byte("654321"),
				SecretDataKeyRaw: rawValid,
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-error",
			resp: respValid,
			opt: &SecretTransformationOption{
				Excludes: []string{"(foo"},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"error parsing regexp: missing closing ): `(foo`", i...)
			},
		},
		{
			name: "valid-unsupported-type",
			resp: respValidUnsupportedType,
			want: map[string][]byte{
				"biff":           []byte("baz"),
				SecretDataKeyRaw: rawUnsupportedType,
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-contains-raw",
			resp: respContainsRaw,
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, SecretDataErrorContainsRaw)
			},
		},
		{
			name: "exclude-raw",
			resp: respValid,
			opt: &SecretTransformationOption{
				ExcludeRaw: true,
			},
			want: map[string][]byte{
				"bar":                     []byte("foo"),
				"foo":                     []byte("qux"),
				"rotatingfoo_api_key_one": []byte("123456"),
				"rotatingfoo_api_key_two": []byte("654321"),
				"rotatingfoo":             rotatingValueRaw,
				"dyn":                     dynValueRaw,
				"dyn_val_one":             []byte("123456"),
				"dyn_val_two":             []byte("654321"),
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			s := &SecretDataBuilder{}
			got, err := s.WithHVSAppSecrets(tt.resp, tt.opt)
			if !tt.wantErr(t, err, fmt.Sprintf("WithHVSAppSecrets(%v, %v)", tt.resp, tt.opt)) {
				return
			}
			assert.Equalf(t, tt.want, got, "WithHVSAppSecrets(%v, %v)", tt.resp, tt.opt)
		})
	}
}

func TestHasOwnerLabels(t *testing.T) {
	t.Parallel()

	// label setup copied to controllers.Test_secretsPredicate_Delete()
	require.Greater(t, len(OwnerLabels), 1, "OwnerLabels global is invalid,")

	hasNotLabels := maps.Clone(OwnerLabels)
	for k := range hasNotLabels {
		delete(hasNotLabels, k)
		break
	}

	tests := []struct {
		name string
		o    ctrlclient.Object
		want bool
	}{
		{
			name: "has",
			o: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Labels: OwnerLabels,
				},
			},
			want: true,
		},
		{
			name: "has-not",
			o: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Labels: hasNotLabels,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			assert.Equalf(t, tt.want, HasOwnerLabels(tt.o), "HasOwnerLabels(%v)", tt.o)
		})
	}
}

func TestHVSShadowSecretData(t *testing.T) {
	now := time.Now()
	secrets := []*models.Secrets20231128OpenSecret{
		{
			CreatedAt:     strfmt.DateTime(now),
			CreatedByID:   "some uuid",
			LatestVersion: 1,
			Name:          "bar",
			Provider:      "providerfoo",
			SyncStatus:    nil,
			Type:          HVSSecretTypeDynamic,
			DynamicInstance: &models.Secrets20231128OpenSecretDynamicInstance{
				CreatedAt: strfmt.DateTime(now),
				ExpiresAt: strfmt.DateTime(now.Add(1 * time.Hour)),
				TTL:       "3600s",
				Values: map[string]string{
					"api_key_one": "123456",
					"api_key_two": "654321",
				},
			},
		},
	}

	k8sShadowData, err := MakeHVSShadowSecretData(secrets)
	require.NoError(t, err)

	roundTripSecrets, err := FromHVSShadowSecret(k8sShadowData["bar"])
	require.NoError(t, err)

	checkDynamicOpenSecretEqual(t, secrets[0], roundTripSecrets)

	// Store the shadow data again in a secret
	k8sShadowData2, err := MakeHVSShadowSecretData([]*models.Secrets20231128OpenSecret{
		roundTripSecrets,
	})
	require.NoError(t, err)

	// Ensure the shadow data is the same
	assert.Equal(t, k8sShadowData, k8sShadowData2)

	// Ensure the data conversion still comes back equal to the original
	roundTripSecrets2, err := FromHVSShadowSecret(k8sShadowData2["bar"])
	require.NoError(t, err)

	checkDynamicOpenSecretEqual(t, secrets[0], roundTripSecrets2)
}

func checkDynamicOpenSecretEqual(t *testing.T, want, got *models.Secrets20231128OpenSecret) {
	t.Helper()

	assert.Equal(t, want.CreatedAt.String(), got.CreatedAt.String())
	assert.Equal(t, want.CreatedByID, got.CreatedByID)
	assert.Equal(t, want.LatestVersion, got.LatestVersion)
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Provider, got.Provider)
	assert.Equal(t, want.SyncStatus, got.SyncStatus)
	assert.Equal(t, want.Type, got.Type)

	assert.Equal(t, want.DynamicInstance.CreatedAt.String(),
		got.DynamicInstance.CreatedAt.String())
	assert.Equal(t, want.DynamicInstance.ExpiresAt.String(),
		got.DynamicInstance.ExpiresAt.String())
	assert.Equal(t, want.DynamicInstance.TTL, got.DynamicInstance.TTL)
	assert.Equal(t, want.DynamicInstance.Values, got.DynamicInstance.Values)
}
