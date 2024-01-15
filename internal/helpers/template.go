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
	Excludes    []string
	Includes    []string
	Specs       map[string]secretsv1beta1.Template
	Annotations map[string]string
	Labels      map[string]string
}

func NewSecretRenderOption(ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object,
) (*SecretTransformationOption, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, err
	}

	specs, err := gatherTemplateSpecs(ctx, client, meta)
	if err != nil {
		return nil, err
	}

	return &SecretTransformationOption{
		Excludes:    meta.Destination.Transformation.Excludes,
		Includes:    meta.Destination.Transformation.Includes,
		Specs:       specs,
		Annotations: obj.GetAnnotations(),
		Labels:      obj.GetLabels(),
	}, nil
}

// gatherTemplateSpecs attempts to collect all v1beta1.Template for the
// syncable secret object.
func gatherTemplateSpecs(ctx context.Context, client ctrlclient.Client,
	meta *common.SyncableSecretMetaData,
) (map[string]secretsv1beta1.Template, error) {
	var errs error
	specs := make(map[string]secretsv1beta1.Template)
	addSpec := func(name string, spec secretsv1beta1.Template, replace bool) {
		if !replace {
			// spec.Name is the name of the template, which are not allowed
			// to collide when taking the union of all templates.
			if _, ok := specs[name]; ok {
				errs = errors.Join(errs,
					fmt.Errorf("failed to gather templates, "+
						"duplicate template spec name %q", name))
				return
			}
		}

		if err := validateTemplateSpec(spec); err != nil {
			errs = errors.Join(errs, err)
			return
		}

		specs[name] = spec
	}

	transformation := meta.Destination.Transformation
	// get the in-line template specs
	for name, spec := range transformation.Templates {
		if !spec.Source && spec.KeyOverride == "" {
			spec.KeyOverride = name
		}
		addSpec(name, spec, false)
	}

	seenRefs := make(map[string]bool)
	// TODO: cache ref results
	// get the remote ref template specs
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

		// hasOverrides means that only a subset of Templates are needed, we still
		// need to include all the reference Templates when rendering the subset of
		// all specs. We treat those specs as being a template source only.
		hasOverrides := len(ref.TemplateRefSpecs) > 0
		for name, s := range obj.Spec.Templates {
			if _, ok := transformation.Templates[name]; ok {
				// inline specs take precedence
				continue
			}

			if hasOverrides {
				// if we have TemplateRefSpecs then all referenced Templates are treated as a
				// template source.
				// s = *s.DeepCopy()
				s.Source = true
			}
			addSpec(name, s, false)
		}

		for name, refSpec := range ref.TemplateRefSpecs {
			if _, ok := transformation.Templates[name]; ok {
				// inline specs take precedence over
				continue
			}

			spec, ok := obj.Spec.Templates[name]
			// get the template spec
			if !ok {
				errs = errors.Join(errs,
					fmt.Errorf(
						"template %q not found in object %s, %s",
						name, objKey, obj.GetObjectKind().GroupVersionKind()))
				continue
			}

			key := spec.KeyOverride
			if key == "" {
				// spec.KeyOverride is empty, then set it from spec's
				key = refSpec.Key
			}

			source := refSpec.Source
			if !source {
				source = spec.Source
			}

			addSpec(name, secretsv1beta1.Template{
				KeyOverride: key,
				Text:        spec.Text,
				Source:      source,
			}, true)
		}
	}

	if errs != nil {
		return nil, errs
	}

	return specs, nil
}

// loadTemplates parses all v1beta1.Template into a single
// template.SecretTemplate. It should normally be called before rendering any of
// the template.
func loadTemplates(opt *SecretTransformationOption) (template.SecretTemplate, error) {
	var t template.SecretTemplate
	for name, spec := range opt.Specs {
		if t == nil {
			t = template.NewSecretTemplate("")
		}

		if err := t.Parse(name, spec.Text); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// renderTemplates from the SecretTransformationOption and SecretInput.
func renderTemplates(opt *SecretTransformationOption,
	input *SecretInput,
) (map[string][]byte, error) {
	if len(opt.Specs) == 0 {
		return nil, fmt.Errorf("no template specs configured")
	}

	data := make(map[string][]byte)
	tmpl, err := loadTemplates(opt)
	if err != nil {
		return nil, err
	}

	for name, spec := range opt.Specs {
		if spec.Source {
			continue
		}

		if err := validateTemplateSpec(spec); err != nil {
			return nil, err
		}

		b, err := tmpl.ExecuteTemplate(name, input)
		if err != nil {
			return nil, err
		}
		data[spec.KeyOverride] = b
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

func validateTemplateSpec(spec secretsv1beta1.Template) error {
	if !spec.Source && spec.KeyOverride == "" {
		// TODO: add more context to this error
		return fmt.Errorf(
			"key cannot be empty when source is false")
	}

	return nil
}
