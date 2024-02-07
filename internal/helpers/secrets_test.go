// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/go-openapi/strfmt"
	hvsclient "github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/client/secret_service"
	"github.com/hashicorp/hcp-sdk-go/clients/cloud-vault-secrets/preview/2023-06-13/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
)

func TestFindSecretsOwnedByObj(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()
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
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()

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
		obj                *secretsv1beta1.VaultDynamicSecret
		data               map[string][]byte
		orphans            int
		createDest         bool
		destLabels         map[string]string
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
		{
			name:               "invalid-dest-exists-no-create-overwrite",
			client:             clientBuilder.Build(),
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
			client:             clientBuilder.Build(),
			obj:                ownerWithDestOverwrite,
			createDest:         true,
			expectSecretsCount: 1,
			wantErr:            assert.NoError,
		},
		{
			name:               "dest-exists-owned-overwrite-true",
			client:             clientBuilder.Build(),
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
						Name:      tt.obj.Spec.Destination.Name,
						Namespace: tt.obj.GetNamespace(),
						Labels:    tt.destLabels,
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
		Payload: &models.Secrets20230613OpenAppSecretsResponse{
			Secrets: []*models.Secrets20230613OpenSecret{
				{
					CreatedAt: strfmt.NewDateTime(),
					CreatedBy: &models.Secrets20230613Principal{
						Name: "vso",
					},
					LatestVersion: "",
					Name:          "bar",
					SyncStatus:    nil,
					Version: &models.Secrets20230613OpenSecretVersion{
						CreatedAt: strfmt.DateTime{},
						CreatedBy: &models.Secrets20230613Principal{
							Name: "vso-0",
						},
						Type:    "kv",
						Value:   "foo",
						Version: "1",
					},
				},
				{
					CreatedAt: strfmt.NewDateTime(),
					CreatedBy: &models.Secrets20230613Principal{
						Name: "vso-1",
					},
					LatestVersion: "",
					Name:          "foo",
					SyncStatus:    nil,
					Version: &models.Secrets20230613OpenSecretVersion{
						CreatedAt: strfmt.DateTime{},
						CreatedBy: &models.Secrets20230613Principal{
							Name: "vso-1",
						},
						Type:  "kv",
						Value: "qux",
					},
				},
			},
		},
	}

	rawValid, err := respValid.GetPayload().MarshalBinary()
	require.NoError(t, err)

	respValidUnsupportedType := &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20230613OpenAppSecretsResponse{
			Secrets: []*models.Secrets20230613OpenSecret{
				{
					Name: "biff",
					Version: &models.Secrets20230613OpenSecretVersion{
						CreatedAt: strfmt.DateTime{},
						CreatedBy: nil,
						Type:      "kv",
						Value:     "baz",
					},
				},
				{
					Name: "baz",
					Version: &models.Secrets20230613OpenSecretVersion{
						CreatedAt: strfmt.DateTime{},
						CreatedBy: nil,
						Type:      "_unsupported_",
						Value:     "qux",
					},
				},
			},
		},
	}

	rawUnsupportedType, err := respValidUnsupportedType.GetPayload().MarshalBinary()
	require.NoError(t, err)

	respContainsRaw := &hvsclient.OpenAppSecretsOK{
		Payload: &models.Secrets20230613OpenAppSecretsResponse{
			Secrets: []*models.Secrets20230613OpenSecret{
				{
					CreatedAt:     strfmt.DateTime{},
					CreatedBy:     nil,
					LatestVersion: "",
					Name:          SecretDataKeyRaw,
					SyncStatus:    nil,
					Version: &models.Secrets20230613OpenSecretVersion{
						CreatedAt: strfmt.DateTime{},
						CreatedBy: nil,
						Type:      "kv",
						Value:     "foo",
						Version:   "",
					},
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
				"bar":            []byte("foo"),
				"foo":            []byte("qux"),
				SecretDataKeyRaw: rawValid,
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
				"bar":            []byte("FOO"),
				"foo":            []byte("qux"),
				SecretDataKeyRaw: rawValid,
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
				},
			},
			want: map[string][]byte{
				"metadata.json": []byte(`{
  "bar": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "created_by": {
      "name": "vso"
    },
    "name": "bar",
    "version": {
      "created_at": "0001-01-01T00:00:00.000Z",
      "created_by": {
        "name": "vso-0"
      },
      "type": "kv",
      "version": "1"
    }
  },
  "foo": {
    "created_at": "1970-01-01T00:00:00.000Z",
    "created_by": {
      "name": "vso-1"
    },
    "name": "foo",
    "version": {
      "created_at": "0001-01-01T00:00:00.000Z",
      "created_by": {
        "name": "vso-1"
      },
      "type": "kv"
    }
  }
}`,
				),
				"bar":            []byte("foo"),
				"foo":            []byte("qux"),
				SecretDataKeyRaw: rawValid,
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
				},
				Excludes: []string{"foo"},
			},
			want: map[string][]byte{
				"bar":            []byte("FOO"),
				SecretDataKeyRaw: rawValid,
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
				"foo":            []byte("qux"),
				SecretDataKeyRaw: rawValid,
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
				"bar": []byte("foo"),
				"foo": []byte("qux"),
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
