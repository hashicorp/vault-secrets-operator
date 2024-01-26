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
	"sync"

	"github.com/hashicorp/golang-lru/v2"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/template"
)

var regexCache *lru.Cache[string, *regexp.Regexp]

func init() {
	var err error
	regexCache, err = lru.New[string, *regexp.Regexp](250)
	if err != nil {
		panic(err)
	}
}

// SecretTransformationOption holds all Templates and field filters for a given
// Destination
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
	// KeyedTemplates contains the derived set of all templates.
	KeyedTemplates []*KeyedTemplate
}

type KeyedTemplate struct {
	// Key that will be used as the K8s Secret data key. In the case where Key is
	// empty, then Template is treated as source only, and will not be included in
	// the K8s Secret data.
	Key string
	// Template that will be rendered for Key
	Template secretsv1beta1.Template
}

func (k *KeyedTemplate) Cmp(other *KeyedTemplate) int {
	return cmp.Compare(
		// source templates should come first, e.g key == ""
		k.Key+"0"+k.Template.Name,
		other.Key+"0"+other.Template.Name,
	)
}

func NewSecretRenderOption(ctx context.Context, client ctrlclient.Client,
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

	return &SecretTransformationOption{
		Excludes:       ff.excludes(),
		Includes:       ff.includes(),
		KeyedTemplates: keyedTemplates,
		Annotations:    obj.GetAnnotations(),
		Labels:         obj.GetLabels(),
	}, nil
}

// gatherTemplates attempts to collect all v1beta1.Template(s) for the
// syncable secret object.
func gatherTemplates(ctx context.Context, client ctrlclient.Client, meta *common.SyncableSecretMetaData) ([]*KeyedTemplate, *fieldFilter, error) {
	var errs error
	var keyedTemplates []*KeyedTemplate

	templates := make(map[string]secretsv1beta1.Template)
	addTemplate := func(tmpl secretsv1beta1.Template, key string) {
		if _, ok := templates[tmpl.Name]; ok {
			errs = errors.Join(errs,
				fmt.Errorf("failed to gather templates, "+
					"duplicate template name %q", tmpl.Name))
			return
		}

		if err := validateTemplate(tmpl); err != nil {
			errs = errors.Join(errs, err)
			return
		}

		templates[tmpl.Name] = tmpl
		keyedTemplates = append(keyedTemplates, &KeyedTemplate{
			Key:      key,
			Template: tmpl,
		})
	}

	ff := &fieldFilter{}
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

	seenRefs := make(map[string]bool)
	// TODO: cache ref results
	// get the remote ref template templates
	for _, ref := range transformation.TransformationRefs {
		// TODO: decide on a policy for restricting access to SecretTransformations
		// TODO: support getting SecretTransformations by label, potentially
		// TODO: consider only supporting a single SecretTransformation ref?
		ns := meta.Namespace
		if ref.Namespace != "" {
			ns = ref.Namespace
		}

		objKey := ctrlclient.ObjectKey{Namespace: ns, Name: ref.Name}
		if _, ok := seenRefs[objKey.String()]; ok {
			errs = errors.Join(errs,
				fmt.Errorf("duplicate SecretTransformation ref %s", objKey))
			continue
		}

		seenRefs[objKey.String()] = true

		obj, err := common.GetSecretTransformation(ctx, client, objKey)
		if err != nil {
			errs = errors.Join(errs, err)
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
			if _, ok := templates[tmplRef.Name]; ok {
				errs = errors.Join(errs,
					fmt.Errorf("failed to gather templates, "+
						"duplicate template name %q", tmplRef.Name))
				continue
			}

			tmpl, ok := obj.Spec.Templates[tmplRef.Name]
			// get the template tmpl
			if !ok {
				errs = errors.Join(errs,
					fmt.Errorf(
						"template %q not found in object %s, %s",
						tmplRef.Name, objKey, obj.GetObjectKind().GroupVersionKind()))
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

		// add all configured templates from the SecretTransformation object
		for key, tmpl := range obj.Spec.Templates {
			if _, ok := templates[key]; ok {
				// inline templates take precedence
				continue
			}

			if tmpl.Name == "" {
				tmpl.Name = fmt.Sprintf("%s/%s", objKey, key)
			}

			addTemplate(tmpl, key)
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

// loadTemplates parses all v1beta1.Template into a single
// template.SecretTemplate. It should normally be called before rendering any of
// the template.
func loadTemplates(opt *SecretTransformationOption) (template.SecretTemplate, error) {
	var t template.SecretTemplate
	for _, spec := range opt.KeyedTemplates {
		if t == nil {
			t = template.NewSecretTemplate("")
		}

		if err := t.Parse(spec.Template.Name, spec.Template.Text); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// renderTemplates from the SecretTransformationOption and SecretInput.
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
		if spec.Key == "" {
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

type fieldFilter struct {
	exc sync.Map
	inc sync.Map
}

func (f *fieldFilter) addExcludes(pats ...string) {
	f.add(&f.exc, pats...)
}

func (f *fieldFilter) excludes() []string {
	return f.keys(&f.exc)
}

func (f *fieldFilter) addIncludes(pats ...string) {
	f.add(&f.inc, pats...)
}

func (f *fieldFilter) includes() []string {
	return f.keys(&f.inc)
}

func (f *fieldFilter) add(m *sync.Map, pats ...string) {
	for _, pat := range pats {
		m.LoadOrStore(pat, true)
	}
}

func (f *fieldFilter) keys(m *sync.Map) []string {
	var result []string
	fn := func(key, _ any) bool {
		result = append(result, key.(string))
		return true
	}

	m.Range(fn)

	slices.Sort(result)
	return result
}
