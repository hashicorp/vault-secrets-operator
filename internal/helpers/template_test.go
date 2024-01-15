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
		opt     *SecretTransformationOption
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:  "multi-with-helper",
			input: NewSecretInput[any, any](secrets, nil, nil, nil),
			opt: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"helper": {
						// source template should not be rendered to the K8s Secret
						Source: true,
						Text:   `{{define "helper"}}{{- . | b64dec -}}{{end}}`,
					},
					"t1r": {
						KeyOverride: "t1r",
						Text:        `{{- template "helper" get .Secrets "baz" -}}`,
					},
					"t2r": {
						KeyOverride: "t2r",
						Text:        `{{- template "helper" get .Secrets "bar" -}}`,
					},
					"t3r": {
						KeyOverride: "t3r",
						Text:        `{{- get .Secrets "foo" -}}`,
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
			name: "multi-with-real-world-helper",
			input: NewSecretInput(
				map[string]any{
					"username": "alice",
					"password": "secret",
				}, nil,
				map[string]string{
					"myapp.config/postgres-host": "postgres-postgresql.postgres.svc.cluster.local:5432",
				},
				map[string]string{
					"myapp/name": "db",
				}),
			opt: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"helpers": {
						Source: true,
						Text: `
{{/* 
compose a Postgres URL from SecretInput for this app 
*/}}
{{- define "getPgUrl" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- printf "postgresql://%s:%s@%s/postgres?sslmode=disable" (get .Secrets "username") (get .Secrets "password") $host -}}
{{- end -}}
{{/*
create a Java props from SecretInput for this app
*/}}
{{- define "getAppProps" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- printf "db.host=%s\n" $host -}}
{{- range $k, $v := .Secrets -}}
{{- printf "db.%s=%s\n" $k $v -}}
{{- end -}}
{{- end -}}
{{/* 
create a JSON config from SecretInput for this app
*/}}
{{- define "getAppJson" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- $copy := .Secrets | mustDeepCopy -}}
{{- $_ := set $copy "host" $host -}}
{{- mustToPrettyJson $copy -}}
{{- end -}}
`,
					},
					"url": {
						KeyOverride: "url",
						Text:        `{{- template "getPgUrl" . -}}`,
					},
					"app.props": {
						KeyOverride: "app.props",
						Text:        `{{- template "getAppProps" . -}}`,
					},
					"app.json": {
						KeyOverride: "app.json",
						Text:        `{{- template "getAppJson" . -}}`,
					},
					"app.name": {
						KeyOverride: "app.name",
						Text:        `{{- get .Labels "myapp/name" -}}`,
					},
				},
			},
			want: map[string][]byte{
				"url": []byte(`postgresql://alice:secret@postgres-postgresql.postgres.svc.cluster.local:5432/postgres?sslmode=disable`),
				"app.props": []byte(`db.host=postgres-postgresql.postgres.svc.cluster.local:5432
db.password=secret
db.username=alice
`),
				"app.json": []byte(`{
  "host": "postgres-postgresql.postgres.svc.cluster.local:5432",
  "password": "secret",
  "username": "alice"
}`),
				"app.name": []byte(`db`),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "multi-with-helpers",
			input: NewSecretInput[string, string](secrets, nil, nil, nil),
			opt: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"t1s": {
						// source template should not be rendered to the K8s Secret
						Source: true,
						Text: `{{define "helper1"}}{{- get .Secrets "baz" | b64dec -}}{{end}}
`,
					},
					"ts2": {
						// source template should not be rendered to the K8s Secret
						Source: true,
						Text:   `{{define "helper2"}}{{- get .Secrets "foo" -}}{{end}}`,
					},
					"t1r": {
						KeyOverride: "t1r",
						Text:        `{{- template "helper1" . -}}`,
					},
					"t2r": {
						KeyOverride: "t2r",
						Text:        `{{- template "helper2" . -}}`,
					},
					"t3r": {
						KeyOverride: "t3r",
						Text:        `{{template "helper1" . }}_{{template "helper2" . }}`,
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
			name:  "single-with-metadata-only",
			input: NewSecretInput[string, string](secrets, metadata, nil, nil),
			opt: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"tmpl": {
						KeyOverride: "tmpl",
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
			input: NewSecretInput[string, string](secrets, metadata, nil, nil),
			opt: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"tmpl": {
						KeyOverride: "tmpl",
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
			name:  "no-specs-error",
			input: NewSecretInput[string, string](nil, nil, nil, nil),
			opt:   &SecretTransformationOption{},
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
		opt     *SecretTransformationOption
		d       map[string][]byte
		want    map[string][]byte
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "includes",
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
		opt     *SecretTransformationOption
		d       map[string]any
		want    map[string]any
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "includes",
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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
			opt: &SecretTransformationOption{
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

	defaultTransObjMeta := metav1.ObjectMeta{
		Name:      "templates",
		Namespace: "default",
	}

	dupeTransObjMeta := metav1.ObjectMeta{
		Name:      "dupe",
		Namespace: "default",
	}

	newSecretObj := func(t *testing.T, tf secretsv1beta1.Transformation) ctrlclient.Object {
		t.Helper()

		return &secretsv1beta1.VaultStaticSecret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "basic",
				Namespace: "default",
			},
			Spec: secretsv1beta1.VaultStaticSecretSpec{
				Destination: secretsv1beta1.Destination{
					Transformation: tf,
				},
			},
		}
	}

	newTransObj := func(t *testing.T, objMeta metav1.ObjectMeta, s secretsv1beta1.SecretTransformationSpec) *secretsv1beta1.SecretTransformation {
		t.Helper()

		return &secretsv1beta1.SecretTransformation{
			ObjectMeta: *objMeta.DeepCopy(),
			Spec:       s,
		}
	}

	ctx := context.Background()
	clientBuilder := newClientBuilder()
	tests := []struct {
		name            string
		obj             ctrlclient.Object
		secretTransObjs []*secretsv1beta1.SecretTransformation
		want            *SecretTransformationOption
		wantErr         assert.ErrorAssertionFunc
	}{
		{
			name: "inline-default-2",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					Templates: map[string]secretsv1beta1.Template{
						"default": {
							Text: "{{- -}}",
						},
						"default-2": {
							Text: "{{- -}}",
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			want: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"default": {
						KeyOverride: "default",
						Text:        "{{- -}}",
					},
					"default-2": {
						KeyOverride: "default-2",
						Text:        "{{- -}}",
					},
				},
				Excludes: []string{`^bad.+`},
				Includes: []string{`^good.+`},
			},
			wantErr: assert.NoError,
		},
		{
			name: "inline-default",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					Templates: map[string]secretsv1beta1.Template{
						"default": {
							Text: "{{- -}}",
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			want: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{
					"default": {
						KeyOverride: "default",
						Text:        "{{- -}}",
					},
				},
				Excludes: []string{`^bad.+`},
				Includes: []string{`^good.+`},
			},
			wantErr: assert.NoError,
		},
		{
			name: "filter-only",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					Includes: []string{".+"},
				}),
			want: &SecretTransformationOption{
				Specs:    map[string]secretsv1beta1.Template{},
				Includes: []string{".+"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "refs-default",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Name: "default",
									Key:  "default",
								},
							},
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"other": {
								Text:   "{{- -}}",
								Source: false,
							},
							"default": {
								Text:   "{{- -}}",
								Source: false,
							},
						},
					},
				),
			},
			want: &SecretTransformationOption{
				Excludes: []string{`^bad.+`},
				Includes: []string{`^good.+`},
				Specs: map[string]secretsv1beta1.Template{
					"default": {
						KeyOverride: "default",
						Text:        "{{- -}}",
					},
					"other": {
						Source: true,
						Text:   "{{- -}}",
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "refs-no-ref-specs",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"other": {
								KeyOverride: "baz",
								Text:        "{{- baz -}}",
								Source:      false,
							},
							"default": {
								KeyOverride: "foo",
								Text:        "{{- foo -}}",
								Source:      false,
							},
						},
					},
				),
			},
			want: &SecretTransformationOption{
				Excludes: []string{`^bad.+`},
				Includes: []string{`^good.+`},
				Specs: map[string]secretsv1beta1.Template{
					"other": {
						KeyOverride: "baz",
						Text:        "{{- baz -}}",
						Source:      false,
					},
					"default": {
						KeyOverride: "foo",
						Text:        "{{- foo -}}",
						Source:      false,
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "refs-empty-secret-transformation",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
						},
					},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{},
				),
			},
			want: &SecretTransformationOption{
				Specs: map[string]secretsv1beta1.Template{},
			},
			wantErr: assert.NoError,
		},
		{
			name: "refs-inexistent-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
						},
					},
				},
			),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.True(t, apierrors.IsNotFound(err), i...)
			},
		},
		{
			name: "refs-key-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Source: true,
								},
							},
						},
					},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"other": {
								KeyOverride: "baz",
								Text:        "{{- baz -}}",
								Source:      false,
							},
						},
					},
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template "default" not found in object `+
						`default/templates, secrets.hashicorp.com/v1beta1, `+
						`Kind=SecretTransformation`)
			},
		},
		{
			name: "refs-duplicate",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Key: "other",
								},
							},
						},
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Key: "other",
								},
							},
						},
					},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Text:   "{{- -}}",
								Source: false,
							},
						},
					},
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`duplicate SecretTransformation ref default/templates`)
			},
		},
		{
			name: "refs-key-empty-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {},
							},
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Text:   "{{- -}}",
								Source: false,
							},
						},
					},
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`key cannot be empty when source is false`)
			},
		},
		{
			name: "duplicate-template-name-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Source: true,
								},
							},
						},
						{
							Namespace: "default",
							Name:      "dupe",
							TemplateRefSpecs: map[string]secretsv1beta1.TemplateRefSpec{
								"default": {
									Source: true,
								},
							},
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: []string{`^good.+`},
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Text:   "{{- -}}",
								Source: true,
							},
						},
					},
				),
				newTransObj(t,
					dupeTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Text: "{{- -}}", Source: true,
							},
						},
					},
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`failed to gather templates, `+
						`duplicate template spec name "default"`)
			},
		},
		{
			name: "not-a-syncable-secret-error",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			client := clientBuilder.Build()

			t.Parallel()
			for _, obj := range tt.secretTransObjs {
				require.NoError(t, client.Create(ctx, obj))
			}

			got, err := NewSecretRenderOption(ctx, client, tt.obj)
			if !tt.wantErr(t, err,
				fmt.Sprintf(
					"NewSecretRenderOption(%v, %v, %v)", ctx, client, tt.obj)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"NewSecretRenderOption(%v, %v, %v)", ctx, client, tt.obj)
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
		name        string
		secrets     map[string]any
		metadata    map[string]any
		annotations map[string]string
		labels      map[string]string
		want        *SecretInput
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
			assert.Equalf(t, tt.want, NewSecretInput(tt.secrets, tt.metadata, tt.annotations, tt.labels),
				"NewSecretInput(%v, %v)", tt.secrets, tt.metadata)
		})
	}
}
