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

// SecretRenderOption holds all TemplateSpecs and field filters for a given Destination
type SecretRenderOption struct {
	FieldFilter secretsv1beta1.FieldFilter
	Specs       []secretsv1beta1.TemplateSpec
}

func NewSecretRenderOption(ctx context.Context, client ctrlclient.Client,
	obj ctrlclient.Object,
) (*SecretRenderOption, error) {
	meta, err := common.NewSyncableSecretMetaData(obj)
	if err != nil {
		return nil, err
	}

	specs, err := gatherTemplateSpecs(ctx, client, meta)
	if err != nil {
		return nil, err
	}

	return &SecretRenderOption{
		FieldFilter: meta.Destination.FieldFilter,
		Specs:       specs,
	}, nil
}

// gatherTemplateSpecs attempts to collect all template specs from
func gatherTemplateSpecs(ctx context.Context, client ctrlclient.Client,
	meta *common.SyncableSecretMetaData,
) ([]secretsv1beta1.TemplateSpec, error) {
	var specs []secretsv1beta1.TemplateSpec
	seen := make(map[string]bool)
	var errs error
	appendSpec := func(spec secretsv1beta1.TemplateSpec) {
		if _, ok := seen[spec.Name]; ok {
			errs = errors.Join(errs,
				fmt.Errorf("failed to gather templates, "+
					"duplicate template spec name %q", spec.Name))
			return
		}

		seen[spec.Name] = true
		specs = append(specs, spec)
	}

	// get the in-line template specs
	for _, spec := range meta.Destination.TemplateSpecs {
		appendSpec(spec)
	}

	// TODO: cache ref results
	// get the remote ref template specs
	for _, spec := range meta.Destination.TemplateRefs {
		if len(spec.Specs) == 0 {
			continue
		}

		// TODO: decide on a policy for restricting access to ConfigMap
		// TODO: support getting ConfigMaps by label, potentially
		ns := meta.Namespace
		if spec.Namespace != "" {
			ns = spec.Namespace
		}

		objKey := ctrlclient.ObjectKey{Namespace: ns, Name: spec.Name}
		c, err := GetConfigMap(ctx, client, objKey)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		data := c.Data
		for _, s := range spec.Specs {
			text, ok := data[s.Key]
			if !ok {
				errs = errors.Join(errs,
					fmt.Errorf(
						"template %q not found in object %s, "+
							"kind=ConfigMap",
						s.Key, objKey))
				continue
			}
			appendSpec(secretsv1beta1.TemplateSpec{
				Name:   s.Name,
				Text:   text,
				Render: s.Render,
			})
		}
	}

	if errs != nil {
		return nil, errs
	}

	return specs, nil
}

// loadTemplates parses all v1beta1.TemplateSpec into a single
// template.SecretTemplate. It should normally be called before rendering any of
// the template.
func loadTemplates(opt *SecretRenderOption) (template.SecretTemplate, error) {
	seen := make(map[string]bool)
	var t template.SecretTemplate
	for _, spec := range opt.Specs {
		if _, ok := seen[spec.Name]; ok {
			return nil, fmt.Errorf("failed to load template, "+
				"duplicate template spec name %q", spec.Name)
		}

		seen[spec.Name] = true
		if t == nil {
			t = template.NewSecretTemplate("")
		}

		if err := t.Parse(spec.Name, spec.Text); err != nil {
			return nil, err
		}
	}

	return t, nil
}

// renderTemplates from the SecretRenderOption and SecretInput.
func renderTemplates(opt *SecretRenderOption, input *SecretInput) (map[string][]byte, error) {
	if len(opt.Specs) == 0 {
		return nil, fmt.Errorf("no template specs configured")
	}

	data := make(map[string][]byte)
	tmpl, err := loadTemplates(opt)
	if err != nil {
		return nil, err
	}

	for _, spec := range opt.Specs {
		if !spec.Render {
			continue
		}

		d, err := tmpl.ExecuteTemplate(spec.Name, input)
		if err != nil {
			return nil, err
		}
		data[spec.Name] = d[spec.Name]
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

// filterFields filters data using v1beta1.FieldFilter's exclude/include
// regex patterns, with processing done in that order.
func filterFields[V any](f *secretsv1beta1.FieldFilter, data map[string]V) (map[string]V, error) {
	hasExcludes := len(f.Excludes) > 0
	if !hasExcludes && len(f.Includes) == 0 {
		return data, nil
	}

	m := make(map[string]V)
	for k := range data {
		if !hasExcludes {
			// copy d -> m
			m[k] = data[k]
			continue
		}

		for _, pat := range f.Excludes {
			if matched, err := matchField(pat, k); err != nil {
				return nil, err
			} else if !matched {
				m[k] = data[k]
			}
		}
	}

	for k := range m {
		for _, pat := range f.Includes {
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
}

// NewSecretInput sets up a SecretInput instance from the provided secret data
// and secret metadata.
func NewSecretInput(secrets, metadata map[string]any) *SecretInput {
	return &SecretInput{
		Secrets:  secrets,
		Metadata: metadata,
	}
}
