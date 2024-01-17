// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"errors"
	"fmt"
	"regexp"

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
	Excludes       []string
	Includes       []string
	KeyedTemplates []KeyedTemplate
	Annotations    map[string]string
	Labels         map[string]string
}

type KeyedTemplate struct {
	// Key that will be used as the K8s Secret data key. In the case where Key is
	// empty, then Template is treated as source only, and will not be included in
	// the K8s Secret data.
	Key string
	// Template that will be rendered for Key
	Template secretsv1beta1.Template
}

func NewSecretRenderOption(ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object,
) (*SecretTransformationOption, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, err
	}

	keyedTemplates, err := gatherTemplateSpecs(ctx, client, meta)
	if err != nil {
		return nil, err
	}

	return &SecretTransformationOption{
		Excludes:       meta.Destination.Transformation.Excludes,
		Includes:       meta.Destination.Transformation.Includes,
		KeyedTemplates: keyedTemplates,
		Annotations:    obj.GetAnnotations(),
		Labels:         obj.GetLabels(),
	}, nil
}

// lots of confusion between key name and template name...
// gatherTemplateSpecs attempts to collect all v1beta1.Template(s) for the
// syncable secret object.
func gatherTemplateSpecs(ctx context.Context, client ctrlclient.Client,
	meta *common.SyncableSecretMetaData,
) ([]KeyedTemplate, error) {
	var errs error
	templates := make(map[string]secretsv1beta1.Template)
	var keyedTemplates []KeyedTemplate
	addTemplate := func(tmpl secretsv1beta1.Template) {
		if _, ok := templates[tmpl.Name]; ok {
			errs = errors.Join(errs,
				fmt.Errorf("failed to gather templates, "+
					"duplicate template name %q", tmpl.Name))
			return
		}

		if err := validateTemplateSpec(tmpl); err != nil {
			errs = errors.Join(errs, err)
			return
		}

		templates[tmpl.Name] = tmpl
	}

	addKeyedTemplate := func(tmpl secretsv1beta1.Template, key string) {
		addTemplate(tmpl)
		keyedTemplates = append(keyedTemplates, KeyedTemplate{
			Key:      key,
			Template: tmpl,
		})
	}

	transformation := meta.Destination.Transformation

	// get the in-line template templates
	for key, tmpl := range transformation.Templates {
		name := tmpl.Name
		if name == "" {
			name = key
		}
		addKeyedTemplate(tmpl, key)
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

			addKeyedTemplate(tmpl, key)
		}

		// TODO: does the templating naming scheme make sense?
		for idx, tmpl := range obj.Spec.SourceTemplates {
			name := tmpl.Name
			if name == "" {
				name = fmt.Sprintf("%s/%d", objKey, idx)
			}

			addKeyedTemplate(
				secretsv1beta1.Template{
					Name: tmpl.Name,
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

			addKeyedTemplate(tmpl, key)
		}
	}

	if errs != nil {
		return nil, errs
	}

	return keyedTemplates, nil
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

		if err := validateTemplateSpec(spec.Template); err != nil {
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

	return re.MatchString(f), nil
}

// filterFields filters data using SecretTransformationOption's exclude/include
// regex patterns, with processing done in that order. If filter is nil, return
// all data, unfiltered.
func filterFields[V any](filter *SecretTransformationOption, data map[string]V) (map[string]V, error) {
	if filter == nil {
		return data, nil
	}

	hasExcludes := len(filter.Excludes) > 0
	if !hasExcludes && len(filter.Includes) == 0 {
		return data, nil
	}

	m := make(map[string]V)
	for k := range data {
		if !hasExcludes {
			// copy d -> m
			m[k] = data[k]
			continue
		}

		for _, pat := range filter.Excludes {
			if matched, err := matchField(pat, k); err != nil {
				return nil, err
			} else if !matched {
				m[k] = data[k]
			}
		}
	}

	for k := range m {
		for _, pat := range filter.Includes {
			if matched, err := matchField(pat, k); err != nil {
				return nil, err
			} else if !matched {
				delete(m, k)
			}
		}
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

func validateTemplateSpec(tmpl secretsv1beta1.Template) error {
	if tmpl.Name == "" {
		// TODO: add more context to this error
		return fmt.Errorf(
			"template name cannot empty")
	}

	return nil
}
