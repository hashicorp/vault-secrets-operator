// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"fmt"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
)

func Test_defaultSecretTemplate_ExecuteTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		texts          map[string]string
		m              any
		want           map[string][]byte
		tmpl           SecretTemplate
		tmplName       string
		noRedactErrors bool
		wantRenderErr  assert.ErrorAssertionFunc
		wantParseErr   assert.ErrorAssertionFunc
	}{
		{
			name:     "empty",
			tmpl:     NewSecretTemplate("template"),
			tmplName: "empty",
			texts: map[string]string{
				"empty": "",
			},
			want: map[string][]byte{
				"empty": nil,
			},
			wantRenderErr: assert.NoError,
			wantParseErr:  assert.NoError,
		},
		{
			name:     "multi-first",
			tmpl:     NewSecretTemplate("template"),
			tmplName: "tmpl1",
			texts: map[string]string{
				"tmpl1": `{{- print "foo" -}}`,
				"tmpl2": `{{- print "bar" -}}`,
			},
			want: map[string][]byte{
				"tmpl1": []byte("foo"),
			},
			wantRenderErr: assert.NoError,
			wantParseErr:  assert.NoError,
		},
		{
			name:     "multi-last",
			tmpl:     NewSecretTemplate("template"),
			tmplName: "tmpl2",
			texts: map[string]string{
				"tmpl1": `{{- print "foo" -}}`,
				"tmpl2": `{{- print "bar" -}}`,
			},
			want: map[string][]byte{
				"tmpl2": []byte("bar"),
			},
			wantRenderErr: assert.NoError,
			wantParseErr:  assert.NoError,
		},
		{
			name:     "uninitialized-error`",
			tmpl:     &defaultSecretTemplate{},
			tmplName: "tmpl1",
			texts: map[string]string{
				"tmpl1": `{{- print "foo" -}}`,
				"tmpl2": `{{- print "bar" -}}`,
			},
			want: nil,
			wantParseErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "template not initialized")
			},
			wantRenderErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err, "template not initialized")
			},
		},
		{
			// should result in a range error that is redacted since can leak confidential
			// information.
			name: "range-over-error-redacted-2",
			tmpl: &defaultSecretTemplate{
				noRedactErrors: false,
				tmpl:           template.New("tmpl1").Funcs(funcMap),
			},
			tmplName: "tmpl1",
			m: struct {
				Map map[string]any
			}{
				Map: map[string]any{
					"secret": "revealed",
				},
			},
			texts: map[string]string{
				"tmpl1": `
        {{- range $key, $value := . -}}
        {{- printf "%s=%s\n" $key ( $value | b64enc ) -}}
        {{- end }}`,
			},
			wantParseErr: assert.NoError,
			wantRenderErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template: tmpl1:2:34: executing "tmpl1" at <.>: `+
						`range can't iterate over <redacted>`,
				)
			},
		},
		{
			// should result in a range error that is not redacted, for test purposes only
			name: "range-over-error-no-redaction",
			tmpl: &defaultSecretTemplate{
				noRedactErrors: true,
				tmpl:           template.New("tmpl1").Funcs(funcMap),
			},
			tmplName: "tmpl1",
			m: struct {
				Map map[string]any
			}{
				Map: map[string]any{
					"secret": "revealed",
				},
			},
			texts: map[string]string{
				"tmpl1": `
        {{- range $key, $value := . -}}
        {{- printf "%s=%s\n" $key ( $value | b64enc ) -}}
        {{- end }}`,
			},
			wantParseErr: assert.NoError,
			wantRenderErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template: tmpl1:2:34: executing "tmpl1" at <.>: `+
						`range can't iterate over {map[secret:revealed]}`,
				)
			},
		},
		{
			name:     "parse-error`",
			tmpl:     NewSecretTemplate("template"),
			tmplName: "tmpl1",
			texts: map[string]string{
				// invalid
				"tmpl1": `{{- print "foo" -}`,
				// valid canary
				"tmpl2": `{{- print "bar" -}}`,
			},
			want: nil,
			wantParseErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template: tmpl1:1: illegal number syntax: "-"`,
				)
			},
			wantRenderErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					`template: no template "tmpl1" associated with `+
						`template "template"`,
				)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()

			for name, text := range tt.texts {
				if err := tt.tmpl.Parse(name, text); err != nil {
					if !tt.wantParseErr(t, err, fmt.Sprintf("Parse(%v, %v)", name, text)) {
						return
					}
				}
			}

			got, err := tt.tmpl.ExecuteTemplate(tt.tmplName, tt.m)
			if !tt.wantRenderErr(t, err, fmt.Sprintf("ExecuteTemplate(%v, %v)", tt.tmplName, tt.m)) {
				return
			}

			assert.Equalf(t, tt.want, got, "ExecuteTemplate(%v, %v)", tt.name, tt.m)
		})
	}
}

func Test_defaultSecretTemplate_Name(t *testing.T) {
	tests := []struct {
		name string
		tmpl *template.Template
		want string
	}{
		{
			name: "none",
			tmpl: nil,
			want: "",
		},
		{
			name: "set",
			tmpl: template.New("foo"),
			want: "foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultSecretTemplate{
				tmpl: tt.tmpl,
			}
			assert.Equalf(t, tt.want, v.Name(), "Name()")
		})
	}
}

func Test_defaultSecretTemplate_Parse(t *testing.T) {
	tests := []struct {
		name     string
		tmpl     *template.Template
		text     string
		wantName string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "parse`",
			tmpl:     template.New("tmpl1"),
			text:     `{{- print "foo" -}}`,
			wantErr:  assert.NoError,
			wantName: "tmpl1",
		},
		{
			name: "parse-error`",
			tmpl: template.New("tmpl1"),
			text: `{{- print "foo"`,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"template: parse-error`:1: unclosed action",
				)
			},
			wantName: "tmpl1",
		},
		{
			name: "uninitialized-error`",
			tmpl: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.EqualError(t, err,
					"template not initialized",
				)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &defaultSecretTemplate{
				tmpl: tt.tmpl,
			}
			tt.wantErr(t, v.Parse(tt.name, tt.text),
				fmt.Sprintf("Parse(%v, %v)", tt.name, tt.text))

			assert.Equal(t, tt.wantName, v.Name())
		})
	}
}

func TestNewSecretTemplate(t *testing.T) {
	tests := []struct {
		name string
		want SecretTemplate
	}{
		{
			name: "basic",
			want: &defaultSecretTemplate{
				tmpl: template.New("basic").Funcs(funcMap),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSecretTemplate(tt.name)
			assert.Equalf(t, tt.name, got.Name(),
				"NewSecretTemplate(%v)", tt.name)
		})
	}
}
