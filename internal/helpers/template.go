// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/hashicorp/golang-lru/v2"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/template"
)

var (
	// RenderOptionExcludeRaw sets the global sync option for controlling the exclusion
	// of _raw from the destination secret.
	// This is usually set from main via the command line arg --global-rendering-options
	RenderOptionExcludeRaw bool
	// regexCache provides a global LRU cache holding compiled regexes.
	regexCache *lru.Cache[string, *regexp.Regexp]
)

func init() {
	var err error
	regexCache, err = lru.New[string, *regexp.Regexp](250)
	if err != nil {
		panic(err)
	}
}

type DuplicateTemplateNameError struct {
	name string
}

func (e *DuplicateTemplateNameError) Error() string {
	return fmt.Sprintf("duplicate template name %q", e.name)
}

type DuplicateTransformationRefError struct {
	objKey ctrlclient.ObjectKey
}

func (e *DuplicateTransformationRefError) Error() string {
	return fmt.Sprintf("duplicate SecretTransformation ref %s", e.objKey)
}

type InvalidSecretTransformationRefError struct {
	objKey ctrlclient.ObjectKey
	gvk    schema.GroupVersionKind
}

func (e *InvalidSecretTransformationRefError) Error() string {
	return fmt.Sprintf(
		"%s is in an invalid state, %s", e.objKey, e.gvk)
}

type TemplateNotFoundError struct {
	name   string
	objKey ctrlclient.ObjectKey
	gvk    schema.GroupVersionKind
}

func (e *TemplateNotFoundError) Error() string {
	return fmt.Sprintf(
		"template %q not found in object %s, %s", e.name, e.objKey, e.gvk)
}

// SecretTransformationOption provides the configuration necessary when
// performing source secret data transformations.
type SecretTransformationOption struct {
	// Excludes contains regex patterns that are applied to the raw secret data. All
	// matches will be excluded for resulting K8s Secret data.
	Excludes []string
	// Includes contains regex patterns that are applied to the raw secret data. All
	// matches will be included in the resulting K8s Secret data.
	Includes []string
	// Annotations to include in the SecretInput.
	Annotations map[string]string
	// Labels to include in the SecretInput.
	Labels map[string]string
	// KeyedTemplates contains the derived set of all templates that will be used
	// during the secret data transformation.
	KeyedTemplates []*KeyedTemplate
	// ExcludeRaw data from the resulting K8s Secret data.
	ExcludeRaw bool
}

// KeyedTemplate maps a secret data key to its secretsv1beta1.Template
type KeyedTemplate struct {
	// Key that will be used as the K8s Secret data key. In the case where Key is
	// empty, then Template is treated as source only, and will not be included in
	// the final K8s Secret data.
	Key string
	// Template that will be rendered for Key
	Template secretsv1beta1.Template
}

// IsSource returns true if the KeyedTemplate should be treated as a template
// source only.
func (k *KeyedTemplate) IsSource() bool {
	return k.Key == ""
}

func (k *KeyedTemplate) Cmp(other *KeyedTemplate) int {
	return cmp.Compare(
		// source templates should come first, e.g key == ""
		k.Key+"0"+k.Template.Name,
		other.Key+"0"+other.Template.Name,
	)
}

func NewSecretTransformationOption(ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object,
) (*SecretTransformationOption, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, err
	}

	keyedTemplates, ff, err := gatherTemplates(ctx, client, meta)
	if err != nil {
		return nil, err
	}

	excludeRaw := RenderOptionExcludeRaw
	if meta.Destination.Transformation.ExcludeRaw {
		excludeRaw = meta.Destination.Transformation.ExcludeRaw
	}

	return &SecretTransformationOption{
		Excludes:       ff.excludes(),
		Includes:       ff.includes(),
		KeyedTemplates: keyedTemplates,
		Annotations:    obj.GetAnnotations(),
		Labels:         obj.GetLabels(),
		ExcludeRaw:     excludeRaw,
	}, nil
}

// gatherTemplates attempts to collect all v1beta1.Template(s) for the
// syncable secret object.
func gatherTemplates(ctx context.Context, client ctrlclient.Client, meta *common.SyncableSecretMetaData) ([]*KeyedTemplate, *fieldFilters, error) {
	var errs error
	var keyedTemplates []*KeyedTemplate

	// used to deduplicate templates by name
	seenTemplates := make(map[string]secretsv1beta1.Template)
	addTemplate := func(tmpl secretsv1beta1.Template, key string) {
		if _, ok := seenTemplates[tmpl.Name]; ok {
			errs = errors.Join(errs,
				&DuplicateTemplateNameError{name: tmpl.Name})
			return
		}

		if err := validateTemplate(tmpl); err != nil {
			errs = errors.Join(errs, err)
			return
		}

		seenTemplates[tmpl.Name] = tmpl
		keyedTemplates = append(keyedTemplates, &KeyedTemplate{
			Key:      key,
			Template: tmpl,
		})
	}

	ff := newFieldFilters()
	ff.addExcludes(meta.Destination.Transformation.Excludes...)
	ff.addIncludes(meta.Destination.Transformation.Includes...)

	transformation := meta.Destination.Transformation
	// get the in-line template templates
	for key, tmpl := range transformation.Templates {
		name := tmpl.Name
		if name == "" {
			tmpl.Name = fmt.Sprintf("%s/%s/%s", meta.Namespace, meta.Name, key)
		}
		addTemplate(tmpl, key)
	}

	seenRefs := make(map[ctrlclient.ObjectKey]bool)
	// get the remote ref template templates
	for _, ref := range transformation.TransformationRefs {
		ns := meta.Namespace
		if ref.Namespace != "" {
			ns = ref.Namespace
		}

		objKey := ctrlclient.ObjectKey{Namespace: ns, Name: ref.Name}
		if _, ok := seenRefs[objKey]; ok {
			errs = errors.Join(errs,
				&DuplicateTransformationRefError{
					objKey: objKey,
				},
			)
			continue
		}

		seenRefs[objKey] = true

		obj, err := common.GetSecretTransformation(ctx, client, objKey)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		if !obj.Status.Valid {
			errs = errors.Join(errs,
				&InvalidSecretTransformationRefError{
					objKey: objKey,
					gvk:    obj.GetObjectKind().GroupVersionKind(),
				})
			continue
		}

		if !ref.IgnoreExcludes {
			ff.addExcludes(obj.Spec.Excludes...)
		}
		if !ref.IgnoreIncludes {
			ff.addIncludes(obj.Spec.Includes...)
		}

		// add all configured templates for the Destination
		for _, tmplRef := range ref.TemplateRefs {
			if _, ok := seenTemplates[tmplRef.Name]; ok {
				errs = errors.Join(errs,
					&DuplicateTemplateNameError{name: tmplRef.Name})
				continue
			}

			tmpl, ok := obj.Spec.Templates[tmplRef.Name]
			if !ok {
				errs = errors.Join(errs,
					&TemplateNotFoundError{
						name:   tmplRef.Name,
						objKey: objKey,
						gvk:    obj.GetObjectKind().GroupVersionKind(),
					})
				continue
			}

			key := tmplRef.KeyOverride
			if key == "" {
				key = tmplRef.Name
			}

			addTemplate(tmpl, key)
		}

		// add all source templates
		for idx, tmpl := range obj.Spec.SourceTemplates {
			name := tmpl.Name
			if name == "" {
				name = fmt.Sprintf("%s/%d", objKey, idx)
			}

			addTemplate(
				secretsv1beta1.Template{
					Name: name,
					Text: tmpl.Text,
				}, "",
			)
		}

		for key, tmpl := range obj.Spec.Templates {
			// only add key/templates that have not already been seen, first in takes precedence
			if _, ok := seenTemplates[key]; !ok {
				if tmpl.Name == "" {
					tmpl.Name = fmt.Sprintf("%s/%s", objKey, key)
				}

				addTemplate(tmpl, key)
			}
		}
	}

	if errs != nil {
		return nil, nil, errs
	}

	slices.SortFunc(keyedTemplates, func(a, b *KeyedTemplate) int {
		return a.Cmp(b)
	})

	return keyedTemplates, ff, nil
}

// loadTemplates parses all v1beta1.Template(s) into a single
// template.SecretTemplate. It should normally be called before rendering any
// templates
func loadTemplates(opt *SecretTransformationOption) (template.SecretTemplate, error) {
	var t template.SecretTemplate
	for _, tmpl := range opt.KeyedTemplates {
		if t == nil {
			t = template.NewSecretTemplate("")
		}

		if err := t.Parse(tmpl.Template.Name, tmpl.Template.Text); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// renderTemplates from the SecretTransformationOption and SecretInput, returning
// the rendered K8s Secret data.
func renderTemplates(opt *SecretTransformationOption,
	input *SecretInput,
) (map[string][]byte, error) {
	if len(opt.KeyedTemplates) == 0 {
		return nil, fmt.Errorf("no templates configured")
	}

	data := make(map[string][]byte)
	tmpl, err := loadTemplates(opt)
	if err != nil {
		return nil, err
	}

	for _, spec := range opt.KeyedTemplates {
		if spec.IsSource() {
			// an empty key denotes that the template is source only, and will not be
			// included in the final secret data.
			continue
		}

		if err := validateTemplate(spec.Template); err != nil {
			return nil, err
		}

		b, err := tmpl.ExecuteTemplate(spec.Template.Name, input)
		if err != nil {
			return nil, err
		}
		data[spec.Key] = b
	}

	return data, nil
}

func matchField(pat, f string) (bool, error) {
	var err error
	re, ok := regexCache.Get(pat)
	if !ok {
		re, err = regexp.Compile(pat)
		if err != nil {
			return false, err
		}
		regexCache.Add(pat, re)
	}

	matched := re.MatchString(f)
	return matched, nil
}

func filter[V any](d map[string]V, pats []string, f func(matched bool, k string)) error {
	if len(pats) == 0 {
		return nil
	}

	for k := range d {
		var matched bool
		var err error
		for _, pat := range pats {
			matched, err = matchField(pat, k)
			if err != nil {
				return err
			}
			if matched {
				break
			}
		}
		f(matched, k)
	}
	return nil
}

// filterData filters data using SecretTransformationOption's exclude/include
// regex patterns, with processing done in that order. If
// SecretTransformationOption is nil, return all data, unfiltered.
func filterData[V any](opt *SecretTransformationOption, data map[string]V) (map[string]V, error) {
	if opt == nil {
		return data, nil
	}

	hasExcludes := len(opt.Excludes) > 0
	if !hasExcludes && len(opt.Includes) == 0 {
		return data, nil
	}

	m := make(map[string]V)
	if hasExcludes {
		if err := filter(data, opt.Excludes, func(matched bool, k string) {
			if !matched {
				m[k] = data[k]
			}
		}); err != nil {
			return nil, err
		}
	} else {
		m = maps.Clone(data)
	}

	if err := filter(m, opt.Includes, func(matched bool, k string) {
		if !matched {
			delete(m, k)
		}
	}); err != nil {
		return nil, err
	}

	return m, nil
}

// SecretInput provides a standard data structure for secret template rendering.
// It holds the secret data and secret metadata.
type SecretInput struct {
	// Secrets contains the secret data that is considered confidential.
	Secrets map[string]any `json:"secrets"`
	// Metadata contains the secret metadata that is not considered confidential.
	Metadata map[string]any `json:"metadata"`
	// Annotations associated with syncable secret K8s resource
	Annotations map[string]any `json:"annotations"`
	// Labels associated with syncable secret K8s resource
	Labels map[string]any `json:"labels"`
}

// NewSecretInput sets up a SecretInput instance from the provided secret data
// secret metadata, and annotations and labels which are typically of the type
// map[string]string.
func NewSecretInput[A, L any](secrets, metadata map[string]any,
	annotations map[string]A, labels map[string]L,
) *SecretInput {
	var a map[string]any
	if annotations != nil {
		a = make(map[string]any)
		// copy annotations to `a` to ensure it is valid Go template input.
		for k, v := range annotations {
			a[k] = v
		}
	}

	var l map[string]any
	if labels != nil {
		l = make(map[string]any)
		// copy annotations to `a` to ensure it is valid Go template input.
		for k, v := range labels {
			l[k] = v
		}
	}

	return &SecretInput{
		Secrets:     secrets,
		Metadata:    metadata,
		Annotations: a,
		Labels:      l,
	}
}

func validateTemplate(tmpl secretsv1beta1.Template) error {
	if tmpl.Name == "" {
		return fmt.Errorf(
			"template name empty")
	}

	return nil
}

type empty struct{}

// fieldFilters holds the exclude and exclude regex patterns used during secret
// field filtering.
type fieldFilters struct {
	exc map[string]empty
	inc map[string]empty
}

func (f *fieldFilters) addExcludes(pats ...string) {
	f.add(f.exc, pats...)
}

func (f *fieldFilters) excludes() []string {
	return f.keys(f.exc)
}

func (f *fieldFilters) addIncludes(pats ...string) {
	f.add(f.inc, pats...)
}

func (f *fieldFilters) includes() []string {
	return f.keys(f.inc)
}

func (f *fieldFilters) add(m map[string]empty, pats ...string) {
	for _, pat := range pats {
		m[pat] = empty{}
	}
}

func (f *fieldFilters) keys(m map[string]empty) []string {
	var result []string
	for k := range m {
		result = append(result, k)
	}

	slices.Sort(result)
	return result
}

func newFieldFilters() *fieldFilters {
	return &fieldFilters{
		exc: map[string]empty{},
		inc: map[string]empty{},
	}
}
