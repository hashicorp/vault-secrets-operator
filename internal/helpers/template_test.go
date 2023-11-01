// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

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
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
)

func Test_renderTemplates(t *testing.T) {
	t.Parallel()

	secrets := map[string]any{
		"baz": "Zm9v", // decoded value is `foo`
		"bar": "YnV6", // decoded value is `buz`
		"foo": 1,
	}

	metadata := map[string]any{
		"custom": map[string]any{
			"super": "duper",
		},
	}
	tests := []struct {
		name    string
		input   *SecretInput
		opt     *SecretRenderOption
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:  "multi-with-helper",
			input: NewSecretInput(secrets, nil),
			opt: &SecretRenderOption{
				Specs: []secretsv1beta1.TemplateSpec{
					{
						// source template should not be rendered to the K8s Secret
						Name:   "helper",
						Source: true,
						Text:   `{{define "helper"}}{{- . | b64dec -}}{{end}}`,
					},
					{
						Name: "t1r",
						Text: `{{- template "helper" get .Secrets "baz" -}}`,
					},
					{
						Name: "t2r",
						Text: `{{- template "helper" get .Secrets "bar" -}}`,
					},
					{
						Name: "t3r",
						Text: `{{- get .Secrets "foo" -}}`,
					},
				},
			},
			want: map[string][]byte{
				"t1r": []byte(`foo`),
				"t2r": []byte(`buz`),
				"t3r": marshalRaw(t, 1),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "multi-with-helpers",
			input: NewSecretInput(secrets, nil),
			opt: &SecretRenderOption{
				Specs: []secretsv1beta1.TemplateSpec{
					{
						// source template should not be rendered to the K8s Secret
						Name:   "t1s",
						Source: true,
						Text: `{{define "helper1"}}{{- get .Secrets "baz" | b64dec -}}{{end}}
`,
					},
					{
						// source template should not be rendered to the K8s Secret
						Name:   "t2s",
						Source: true,
						Text:   `{{define "helper2"}}{{- get .Secrets "foo" -}}{{end}}`,
					},
					{
						Name: "t1r",
						Text: `{{- template "helper1" . -}}`,
					},
					{
						Name: "t2r",
						Text: `{{- template "helper2" . -}}`,
					},
					{
						Name: "t3r",
						Text: `{{template "helper1" . }}_{{template "helper2" . }}`,
					},
				},
			},
			want: map[string][]byte{
				"t1r": []byte(`foo`),
				"t2r": marshalRaw(t, 1),
				"t3r": []byte(`foo_1`),
			},
			wantErr: assert.NoError,
		},
		{
			name: "single-with-metadata-only",
			input: NewSecretInput(
				secrets,
				metadata),
			opt: &SecretRenderOption{
				Specs: []secretsv1beta1.TemplateSpec{
					{
						Name: "tmpl",
						Text: `{{- $custom := get .Metadata "custom" -}}
{{- get $custom "super" -}}
`,
					},
				},
			},
			want: map[string][]byte{
				"tmpl": []byte(`duper`),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "single-with-both",
			input: NewSecretInput(secrets, metadata),
			opt: &SecretRenderOption{
				Specs: []secretsv1beta1.TemplateSpec{
					{
						Name: "tmpl",
						Text: `{{- $custom := get .Metadata "custom" -}}
{{- printf "%s_%s" (get $custom "super") (get .Secrets "bar" | b64dec) -}}
`,
					},
				},
			},
			want: map[string][]byte{
				"tmpl": []byte(`duper_buz`),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "duplicate-template-error",
			input: NewSecretInput(secrets, nil),
			opt: &SecretRenderOption{
				Specs: []secretsv1beta1.TemplateSpec{
					{
						Name: "t1s",
					},
					{
						Name: "t1s",
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`failed to load template, duplicate template `+
						`spec name "t1s"`, i...)
			},
		},
		{
			name:  "no-specs-error",
			input: NewSecretInput(nil, nil),
			opt:   &SecretRenderOption{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`no template specs configured`, i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			got, err := renderTemplates(tt.opt, tt.input)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"renderTemplates(%v, %v)", tt.opt, tt.input)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"renderTemplates(%v, %v)", tt.opt, tt.input)
		})
	}
}

func TestSecretDataBuilder_filterFields_with_bytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opt     *secretsv1beta1.FieldFilter
		d       map[string][]byte
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "includes",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
				"prefix_2_buz": []byte("foo"),
			},
			want: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "excludes",
			opt: &secretsv1beta1.FieldFilter{
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
				"prefix_2_buz": []byte("foo"),
			},
			want: map[string][]byte{
				"prefix_2_buz": []byte("foo"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "both",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_.+"},
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
				"other_1_baz":  []byte("qux"),
				"prefix_2_foo": []byte("baz"),
				"prefix_2_bar": []byte("baz"),
			},
			want: map[string][]byte{
				"prefix_2_foo": []byte("baz"),
				"prefix_2_bar": []byte("baz"),
			},
			wantErr: assert.NoError,
		},
		{
			name: "both-mutually-exclusive",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_1.+"},
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
			},
			want:    map[string][]byte{},
			wantErr: assert.NoError,
		},
		{
			name: "invalid-includes-regex-error",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^(prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"error parsing regexp: missing closing ): `^(prefix_1.+`")
			},
		},
		{
			name: "invalid-excludes-regex-error",
			opt: &secretsv1beta1.FieldFilter{
				Excludes: []string{"^(prefix_1.+"},
			},
			d: map[string][]byte{
				"prefix_1_foo": []byte("baz"),
				"prefix_1_qux": []byte("bar"),
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"error parsing regexp: missing closing ): `^(prefix_1.+`")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			got, err := filterFields[[]byte](tt.opt, tt.d)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"filterFields(%v, %v)", tt.opt, tt.d)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"filterFields(%v, %v)", tt.opt, tt.d)
		})
	}
}

func TestSecretDataBuilder_filterFields_with_any(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opt     *secretsv1beta1.FieldFilter
		d       map[string]any
		want    map[string]any
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "includes",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_1.+"},
			},
			d: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
				"prefix_2_buz": "foo",
			},
			want: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
			},
			wantErr: assert.NoError,
		},
		{
			name: "excludes",
			opt: &secretsv1beta1.FieldFilter{
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
				"prefix_2_buz": "foo",
			},
			want: map[string]any{
				"prefix_2_buz": "foo",
			},
			wantErr: assert.NoError,
		},
		{
			name: "both",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_.+"},
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
				"other_1_baz":  "qux",
				"prefix_2_foo": "baz",
				"prefix_2_bar": "baz",
			},
			want: map[string]any{
				"prefix_2_foo": "baz",
				"prefix_2_bar": "baz",
			},
			wantErr: assert.NoError,
		},
		{
			name: "both-mutually-exclusive",
			opt: &secretsv1beta1.FieldFilter{
				Includes: []string{"^prefix_1.+"},
				Excludes: []string{"^prefix_1.+"},
			},
			d: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
			},
			want:    map[string]any{},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			got, err := filterFields[any](tt.opt, tt.d)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"filterFields(%v, %v)", tt.opt, tt.d)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"filterFields(%v, %v)", tt.opt, tt.d)
		})
	}
}

func TestNewSecretRenderOption(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clientBuilder := newClientBuilder()
	tests := []struct {
		name       string
		client     ctrlclient.Client
		obj        ctrlclient.Object
		configMaps []*corev1.ConfigMap
		want       *SecretRenderOption
		wantErr    assert.ErrorAssertionFunc
	}{
		{
			name:   "inline-default",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateSpecs: []secretsv1beta1.TemplateSpec{
								{
									Name: "default",
									Text: "{{- -}}",
								},
							},
							TemplateRefs: nil,
							FieldFilter: secretsv1beta1.FieldFilter{
								Excludes: []string{`^bad.+`},
								Includes: []string{`^good.+`},
							},
						},
					},
				},
			},
			want: &SecretRenderOption{
				FieldFilter: secretsv1beta1.FieldFilter{
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
				Specs: []secretsv1beta1.TemplateSpec{
					{
						Name: "default",
						Text: "{{- -}}",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "inline-duplicate-name-error",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateSpecs: []secretsv1beta1.TemplateSpec{
								{
									Name: "default",
									Text: "{{- -}}",
								},
								{
									Name: "default",
									Text: "{{- -}}",
								},
							},
							TemplateRefs: nil,
						},
					},
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`failed to gather templates, `+
						`duplicate template spec name "default"`, i...)
			},
		},
		{
			name:   "not-a-syncable-secret-error",
			client: clientBuilder.Build(),
			obj: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
			},
			want: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`unsupported type *v1.Secret`, i...)
			},
		},
		{
			name:   "filter-only",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							FieldFilter: secretsv1beta1.FieldFilter{
								Includes: []string{".+"},
							},
						},
					},
				},
			},
			want: &SecretRenderOption{
				FieldFilter: secretsv1beta1.FieldFilter{
					Includes: []string{".+"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "refs-default",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Namespace: "default",
									Name:      "templates",
									Specs: []secretsv1beta1.TemplateRefSpec{
										{
											Name: "default",
											Key:  "default",
										},
									},
								},
							},
							FieldFilter: secretsv1beta1.FieldFilter{
								Excludes: []string{`^bad.+`},
								Includes: []string{`^good.+`},
							},
						},
					},
				},
			},
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "templates",
						Namespace: "default",
					},
					Data: map[string]string{
						"default": "{{- -}}",
					},
				},
			},
			want: &SecretRenderOption{
				FieldFilter: secretsv1beta1.FieldFilter{
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
				Specs: []secretsv1beta1.TemplateSpec{
					{
						Name: "default",
						Text: "{{- -}}",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:   "refs-default-no-specs",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Namespace: "default",
									Name:      "templates",
								},
							},
						},
					},
				},
			},
			want:    &SecretRenderOption{},
			wantErr: assert.NoError,
		},
		{
			name:   "refs-configMap-inexistent-error",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Namespace: "default",
									Name:      "templates",
									Specs: []secretsv1beta1.TemplateRefSpec{
										{
											Name: "default",
											Key:  "default",
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.True(t, apierrors.IsNotFound(err), i...)
			},
		},
		{
			name:   "refs-configMap-key-error",
			client: clientBuilder.Build(),
			obj: &secretsv1beta1.VaultStaticSecret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic",
					Namespace: "default",
				},
				Spec: secretsv1beta1.VaultStaticSecretSpec{
					Destination: secretsv1beta1.Destination{
						Transformation: secretsv1beta1.Transformation{
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Namespace: "default",
									Name:      "templates",
									Specs: []secretsv1beta1.TemplateRefSpec{
										{
											Name: "default",
											Key:  "other",
										},
									},
								},
							},
						},
					},
				},
			},
			configMaps: []*corev1.ConfigMap{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "templates",
						Namespace: "default",
					},
					Data: map[string]string{
						"default": "{{- -}}",
					},
				},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template "other" not found in object `+
						`default/templates, kind=ConfigMap`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			for _, cm := range tt.configMaps {
				require.NoError(t, tt.client.Create(ctx, cm))
			}

			got, err := NewSecretRenderOption(ctx, tt.client, tt.obj)
			if !tt.wantErr(t, err,
				fmt.Sprintf(
					"NewSecretRenderOption(%v, %v, %v)", ctx, tt.client, tt.obj)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"NewSecretRenderOption(%v, %v, %v)", ctx, tt.client, tt.obj)
		})
	}
}

func TestNewSecretInput(t *testing.T) {
	secrets := map[string]any{
		"foo":  "baz",
		"biff": 1,
	}
	metadata := map[string]any{
		"custom": map[string]any{
			"buz": "qux",
		},
	}
	tests := []struct {
		name     string
		secrets  map[string]any
		metadata map[string]any
		want     *SecretInput
	}{
		{
			name:    "secrets-only",
			secrets: secrets,
			want: &SecretInput{
				Secrets:  secrets,
				Metadata: nil,
			},
		},
		{
			name:     "metadata-only",
			metadata: metadata,
			want: &SecretInput{
				Secrets:  nil,
				Metadata: metadata,
			},
		},
		{
			name:     "both",
			secrets:  secrets,
			metadata: metadata,
			want: &SecretInput{
				Secrets:  secrets,
				Metadata: metadata,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NewSecretInput(tt.secrets, tt.metadata),
				"NewSecretInput(%v, %v)", tt.secrets, tt.metadata)
		})
	}
}
