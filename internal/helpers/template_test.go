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
	"k8s.io/utils/pointer"
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
				KeyedTemplates: []*KeyedTemplate{
					{
						Template: secretsv1beta1.Template{
							Name: "helper",
							Text: `{{define "helper"}}{{- . | b64dec -}}{{end}}`,
						},
					},
					{
						Key: "t1r",
						Template: secretsv1beta1.Template{
							Name: "t1r",
							Text: `{{- template "helper" get .Secrets "baz" -}}`,
						},
					},
					{
						Key: "t2r",
						Template: secretsv1beta1.Template{
							Name: "t2r",
							Text: `{{- template "helper" get .Secrets "bar" -}}`,
						},
					},
					{
						Key: "t3r",
						Template: secretsv1beta1.Template{
							Name: "t3r",
							Text: `{{- get .Secrets "foo" -}}`,
						},
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
			name:  "multi-with-multi-helpers",
			input: NewSecretInput[string, string](secrets, nil, nil, nil),
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Template: secretsv1beta1.Template{
							Name: "t1s",
							Text: `{{define "helper1"}}{{- get .Secrets "baz" | b64dec -}}{{end}}`,
						},
					},
					{
						Template: secretsv1beta1.Template{
							Name: "t2s",
							Text: `{{define "helper2"}}{{- get .Secrets "foo" -}}{{end}}`,
						},
					},
					{
						Key: "t1r",
						Template: secretsv1beta1.Template{
							Name: "t1r",
							Text: `{{- template "helper1" . -}}`,
						},
					},
					{
						Key: "t2r",
						Template: secretsv1beta1.Template{
							Name: "t2r",
							Text: `{{- template "helper2" . -}}`,
						},
					},
					{
						Key: "t3r",
						Template: secretsv1beta1.Template{
							Name: "t3r",
							Text: `{{template "helper1" . }}_{{template "helper2" . }}`,
						},
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
				KeyedTemplates: []*KeyedTemplate{
					{
						Template: secretsv1beta1.Template{
							Name: "helper",
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
					},
					{
						Key: "url",
						Template: secretsv1beta1.Template{
							Name: "url",
							Text: `{{- template "getPgUrl" . -}}`,
						},
					},
					{
						Key: "app.props",
						Template: secretsv1beta1.Template{
							Name: "app.props",
							Text: `{{- template "getAppProps" . -}}`,
						},
					},
					{
						Key: "app.json",
						Template: secretsv1beta1.Template{
							Name: "app.json",
							Text: `{{- template "getAppJson" . -}}`,
						},
					},
					{
						Key: "app.name",
						Template: secretsv1beta1.Template{
							Name: "app.name",
							Text: `{{- get .Labels "myapp/name" -}}`,
						},
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
			name:  "single-with-metadata-only",
			input: NewSecretInput[string, string](secrets, metadata, nil, nil),
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "tmpl",
						Template: secretsv1beta1.Template{
							Name: "tmpl",
							Text: `{{- $custom := get .Metadata "custom" -}}
			{{- get $custom "super" -}}`,
						},
					},
				},
			},
			want: map[string][]byte{
				"tmpl": []byte(`duper`),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "single-with-secret-and-metadata",
			input: NewSecretInput[string, string](secrets, metadata, nil, nil),
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "tmpl",
						Template: secretsv1beta1.Template{
							Name: "tmpl",
							Text: `{{- $custom := get .Metadata "custom" -}}
			{{- printf "%s_%s" (get $custom "super") (get .Secrets "bar" | b64dec) -}}
			`,
						},
					},
				},
			},
			want: map[string][]byte{
				"tmpl": []byte(`duper_buz`),
			},
			wantErr: assert.NoError,
		},
		{
			name: "single-with-secret-metadata-annotations-and-labels",
			input: NewSecretInput[string, string](secrets, metadata,
				map[string]string{
					"anno1": "foo",
				}, map[string]string{
					"label1": "baz",
				}),
			opt: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "tmpl",
						Template: secretsv1beta1.Template{
							Name: "tmpl",
							Text: `{{- $custom := get .Metadata "custom" -}}
			{{- printf "%s_%s_%s_%s" (get $custom "super") (get .Secrets "bar" | b64dec) (get .Annotations "anno1") (get .Labels "label1") -}}
			`,
						},
					},
				},
			},
			want: map[string][]byte{
				"tmpl": []byte(`duper_buz_foo_baz`),
			},
			wantErr: assert.NoError,
		},
		{
			name:  "no-specs-error",
			input: NewSecretInput[string, string](nil, nil, nil, nil),
			opt:   &SecretTransformationOption{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`no templates configured`, i...)
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

func TestSecretDataBuilder_filterData_with_bytes(t *testing.T) {
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
			got, err := filterData[[]byte](tt.opt, tt.d)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"filterData(%v, %v)", tt.opt, tt.d)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"filterData(%v, %v)", tt.opt, tt.d)
		})
	}
}

func TestSecretDataBuilder_filterData_with_any(t *testing.T) {
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
				Includes: []string{
					"^prefix_1.+",
					"^other_1.+",
				},
			},
			d: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
				"prefix_2_buz": "foo",
				"other_1_baz":  "qux",
			},
			want: map[string]any{
				"prefix_1_foo": "baz",
				"prefix_1_qux": "bar",
				"other_1_baz":  "qux",
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
			got, err := filterData[any](tt.opt, tt.d)
			if !tt.wantErr(t, err, fmt.Sprintf(
				"filterData(%v, %v)", tt.opt, tt.d)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"filterData(%v, %v)", tt.opt, tt.d)
		})
	}
}

func TestNewSecretTransformationOption(t *testing.T) {
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

	newTransObj := func(t *testing.T, objMeta metav1.ObjectMeta,
		spec secretsv1beta1.SecretTransformationSpec,
		status *secretsv1beta1.SecretTransformationStatus,
	) *secretsv1beta1.SecretTransformation {
		t.Helper()

		if status == nil {
			status = &secretsv1beta1.SecretTransformationStatus{
				Valid: pointer.Bool(true),
			}
		}

		return &secretsv1beta1.SecretTransformation{
			ObjectMeta: *objMeta.DeepCopy(),
			Spec:       spec,
			Status:     *status,
		}
	}

	ctx := context.Background()
	clientBuilder := newClientBuilder()

	defaultKeyedTemplates := []*KeyedTemplate{
		{
			Key: "baz",
			Template: secretsv1beta1.Template{
				Name: "default/templates/baz",
				Text: "{{- baz -}}",
			},
		},
		{
			Key: "foo",
			Template: secretsv1beta1.Template{
				Name: "default/templates/foo",
				Text: "{{- foo -}}",
			},
		},
	}
	defaultExcludes := []string{`^bad.+`, `^ugly.+`}
	defaultIncludes := []string{`^good.+`}

	defaultTemplates1 := map[string]secretsv1beta1.Template{
		"baz": {
			Text: "{{- baz -}}",
		},
		"foo": {
			Text: "{{- foo -}}",
		},
	}

	transRefsSingleDefault := []secretsv1beta1.TransformationRef{
		{
			Namespace: "default",
			Name:      "templates",
			TemplateRefs: []secretsv1beta1.TemplateRef{
				{
					Name: "default",
				},
			},
		},
	}
	tests := []struct {
		name            string
		obj             ctrlclient.Object
		globalOpt       *GlobalTransformationOptions
		secretTransObjs []*secretsv1beta1.SecretTransformation
		want            *SecretTransformationOption
		wantErr         assert.ErrorAssertionFunc
	}{
		{
			name: "inline-default",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					Templates: map[string]secretsv1beta1.Template{
						"default-1": {
							Text: "{{- -}}",
						},
						"default-2": {
							Name: "default-2",
							Text: "{{- -}}",
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: defaultIncludes,
				},
			), want: &SecretTransformationOption{
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "default-1",
						Template: secretsv1beta1.Template{
							Name: "default/basic/default-1",
							Text: "{{- -}}",
						},
					},
					{
						Key: "default-2",
						Template: secretsv1beta1.Template{
							Name: "default-2",
							Text: "{{- -}}",
						},
					},
				},
				Excludes: []string{`^bad.+`},
				Includes: defaultIncludes,
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
				Includes: []string{".+"},
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-default",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: transRefsSingleDefault,
					Excludes:           []string{`^bad.+`},
					Includes:           defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						SourceTemplates: []secretsv1beta1.SourceTemplate{
							{
								Text: "{{- qux -}}",
								Name: "named",
							},
							{
								Text: "{{- foo -}}",
							},
						},
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Name: "default",
								Text: "{{- baz -}}",
							},
							"baz": {
								Name: "baz",
								Text: "{{- baz -}}",
							},
						},
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes: []string{`^bad.+`},
				Includes: defaultIncludes,
				KeyedTemplates: []*KeyedTemplate{
					{
						Template: secretsv1beta1.Template{
							Name: "default/templates/1",
							Text: "{{- foo -}}",
						},
					},
					{
						Template: secretsv1beta1.Template{
							Name: "named",
							Text: "{{- qux -}}",
						},
					},
					{
						Key: "default",
						Template: secretsv1beta1.Template{
							Name: "default",
							Text: "{{- baz -}}",
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-only",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
						},
					},
					Excludes: defaultExcludes,
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Excludes:  []string{`^bad.+`, `^amiss`},
						Includes:  []string{`^good.+`, `^a+`},
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       []string{`^amiss`, `^bad.+`, `^ugly.+`},
				Includes:       []string{`^a+`, `^good.+`},
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-only-with-filters",
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
					secretsv1beta1.SecretTransformationSpec{
						Excludes:  []string{`^ugly.+`, `^bad.+`},
						Includes:  defaultIncludes,
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       defaultExcludes,
				Includes:       defaultIncludes,
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-only-ignore-excludes",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace:      "default",
							Name:           "templates",
							IgnoreExcludes: true,
						},
					},
					Excludes: []string{`^ugly.+`, `^bad.+`},
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t, defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Excludes:  []string{`^bad.+`, `^amiss`},
						Includes:  []string{`^good.+`, `^a+`},
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       defaultExcludes,
				Includes:       []string{`^a+`, `^good.+`},
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-only-ignore-excludes",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace:      "default",
							Name:           "templates",
							IgnoreIncludes: true,
						},
					},
					Excludes: defaultExcludes,
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Excludes:  []string{`^bad.+`, `^amiss`},
						Includes:  []string{`^good.+`, `^a+`},
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       []string{`^amiss`, `^bad.+`, `^ugly.+`},
				Includes:       defaultIncludes,
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-only-ignore-excludes-includes",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace:      "default",
							Name:           "templates",
							IgnoreExcludes: true,
							IgnoreIncludes: true,
						},
					},
					Excludes: []string{`^ugly.+`, `^bad.+`},
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Excludes:  []string{`^bad.+`, `^amiss`},
						Includes:  []string{`^good.+`, `^a+`},
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       defaultExcludes,
				Includes:       defaultIncludes,
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-ignore-excludes",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
						},
					},
					Excludes: []string{`^ugly.+`, `^bad.+`},
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: defaultTemplates1,
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes:       defaultExcludes,
				Includes:       defaultIncludes,
				KeyedTemplates: defaultKeyedTemplates,
			},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-empty-secret-transformation",
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
					nil,
				),
			},
			want:    &SecretTransformationOption{},
			wantErr: assert.NoError,
		},
		{
			name: "trans-refs-inexistent-error",
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
			name: "trans-refs-key-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: transRefsSingleDefault,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"other": {
								Name: "other",
								Text: "{{- baz -}}",
							},
						},
					},
					nil,
				),
			},
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorContains(t, err,
					`template "default" not found in object `+
						`default/templates`)
			},
		},
		{
			name: "trans-refs-duplicate",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Name:        "default",
									KeyOverride: "other",
								},
							},
						},
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Name:        "default",
									KeyOverride: "other",
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
								Name: "default",
								Text: "{{- -}}",
							},
						},
					},
					nil,
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`duplicate SecretTransformation ref default/templates`)
			},
		},
		{
			name: "trans-refs-key-override",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Name:        "default",
									KeyOverride: "foo",
								},
							},
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Name: "default",
								Text: "{{- -}}",
							},
						},
					},
					nil,
				),
			},
			want: &SecretTransformationOption{
				Excludes: []string{`^bad.+`},
				Includes: defaultIncludes,
				KeyedTemplates: []*KeyedTemplate{
					{
						Key: "foo",
						Template: secretsv1beta1.Template{
							Name: "default",
							Text: "{{- -}}",
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name: "duplicate-template-name-error",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: []secretsv1beta1.TransformationRef{
						{
							Namespace: "default",
							Name:      "templates",
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Name: "default",
								},
							},
						},
						{
							Namespace: "default",
							Name:      "dupe",
							TemplateRefs: []secretsv1beta1.TemplateRef{
								{
									Name: "default",
								},
							},
						},
					},
					Excludes: []string{`^bad.+`},
					Includes: defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Name: "default",
								Text: "{{- -}}",
							},
						},
					},
					nil,
				),
				newTransObj(t,
					dupeTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Name: "default",
								Text: "{{- -}}",
							},
						},
					},
					nil,
				),
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`duplicate template name "default"`)
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
		{
			name: "inline-duplicate-template-names",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					Templates: map[string]secretsv1beta1.Template{
						"default": {
							Name: "default",
							Text: "{{- -}}",
						},
						"baz": {
							Name: "default",
							Text: "{{- -}}",
						},
					},
				},
			),
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`duplicate template name "default"`, i...)
			},
		},
		{
			name: "trans-refs-invalid-state",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					TransformationRefs: transRefsSingleDefault,
					Excludes:           []string{`^bad.+`},
					Includes:           defaultIncludes,
				},
			),
			secretTransObjs: []*secretsv1beta1.SecretTransformation{
				newTransObj(t,
					defaultTransObjMeta,
					secretsv1beta1.SecretTransformationSpec{
						SourceTemplates: []secretsv1beta1.SourceTemplate{
							{
								Text: "{{- qux -}}",
								Name: "named",
							},
							{
								Text: "{{- foo -}}",
							},
						},
						Templates: map[string]secretsv1beta1.Template{
							"default": {
								Name: "default",
								Text: "{{- baz -}}",
							},
						},
					},
					&secretsv1beta1.SecretTransformationStatus{
						Valid: pointer.Bool(false),
						Error: "",
					}),
			},
			wantErr: func(t assert.TestingT, err error, _ ...interface{}) bool {
				return assert.ErrorContains(t, err,
					`default/templates is in an invalid state`)
			},
		},
		{
			name: "exclude-raw-from-global-opt",
			globalOpt: &GlobalTransformationOptions{
				ExcludeRaw: true,
			},
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{},
			),
			want: &SecretTransformationOption{
				ExcludeRaw: true,
			},
			wantErr: assert.NoError,
		},
		{
			name: "exclude-raw-from-obj",
			obj: newSecretObj(t,
				secretsv1beta1.Transformation{
					ExcludeRaw: true,
				},
			),
			want: &SecretTransformationOption{
				ExcludeRaw: true,
			},
			wantErr: assert.NoError,
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

			got, err := NewSecretTransformationOption(ctx, client, tt.obj, tt.globalOpt)
			if !tt.wantErr(t, err,
				fmt.Sprintf(
					"NewSecretTransformationOption(%v, %v, %v)", ctx, client, tt.obj)) {
				return
			}
			assert.Equalf(t, tt.want, got,
				"NewSecretTransformationOption(%v, %v, %v)", ctx, client, tt.obj)
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

func Test_validateTemplate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    secretsv1beta1.Template
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid",
			tmpl: secretsv1beta1.Template{
				Name: "baz",
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid",
			tmpl: secretsv1beta1.Template{},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template name empty`, i...)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, validateTemplate(tt.tmpl), fmt.Sprintf("validateTemplate(%v)", tt.tmpl))
		})
	}
}
