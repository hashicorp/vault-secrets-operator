// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package template

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"text/template"
)

// tmplErrorRegexes is used to redact confidential information from template
// execution errors that may inadvertently end up in an insecure location.
var tmplErrorRegexes []*regexp.Regexp

func init() {
	// the following regexes should match template execution errors that could reveal
	// confidential information about the template input. The pattern matches should
	// *never* contain confidential information.
	// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.21.3:src/text/template/exec.go;drc=befec5ddbbfbd81ec84e74e15a38044d67f8785b;l=438
	// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.21.3:src/text/template/exec.go;drc=befec5ddbbfbd81ec84e74e15a38044d67f8785b;l=420
	// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.21.3:src/text/template/exec.go;drc=befec5ddbbfbd81ec84e74e15a38044d67f8785b;l=304
	tmplErrorPrefixRe := regexp.MustCompile(
		`^template:`,
	)
	tmplErrorLocationRe := regexp.MustCompile(
		fmt.Sprintf(`%s .+ executing .+ at .+:`, tmplErrorPrefixRe),
	)
	// e.g.: template: tmpl1:2:40: executing "tmpl1" at <"foo">: range can't iterate over map[...
	tmplErrorRe := regexp.MustCompile(
		`range can't iterate over|range over send-only channel|if/with can't use`)
	tmplErrorRegexes = []*regexp.Regexp{
		regexp.MustCompile(
			fmt.Sprintf(`%s %s`,
				tmplErrorLocationRe, tmplErrorRe)),
		regexp.MustCompile(
			fmt.Sprintf(`%s %s`,
				tmplErrorPrefixRe, tmplErrorRe)),
	}
}

var _ SecretTemplate = (*defaultSecretTemplate)(nil)

type SecretTemplate interface {
	Name() string
	Parse(string, string) error
	ExecuteTemplate(string, any) ([]byte, error)
}

type defaultSecretTemplate struct {
	tmpl *template.Template
	mu   sync.RWMutex
	// noRedactErrors disables redacting potentially sensitive information
	// from template execution errors.
	noRedactErrors bool
}

func (v *defaultSecretTemplate) Name() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.tmpl != nil {
		return v.tmpl.Name()
	}
	return ""
}

func (v *defaultSecretTemplate) Parse(name, text string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var tmpl *template.Template
	if v.tmpl == nil {
		return fmt.Errorf("template not initialized")
	} else {
		tmpl = v.tmpl.New(name)
	}

	_, err := tmpl.Parse(text)
	if err != nil {
		return err
	}

	return nil
}

func (v *defaultSecretTemplate) ExecuteTemplate(name string, m any) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.tmpl == nil {
		return nil, fmt.Errorf("template not initialized")
	}

	w := bytes.NewBuffer(nil)
	if err := v.tmpl.ExecuteTemplate(w, name, m); err != nil {
		return nil, v.maybeRedactError(err)
	}

	return w.Bytes(), nil
}

func (v *defaultSecretTemplate) maybeRedactError(err error) error {
	if v.noRedactErrors {
		return err
	}

	for _, re := range tmplErrorRegexes {
		m := re.FindStringSubmatch(err.Error())
		if len(m) > 0 {
			// include the matching messages for context.
			err = fmt.Errorf("%s <redacted>", strings.Join(m, " "))
			break
		}
	}
	return err
}

func NewSecretTemplate(name string) SecretTemplate {
	return &defaultSecretTemplate{
		tmpl: template.New(name).Funcs(funcMap),
	}
}
