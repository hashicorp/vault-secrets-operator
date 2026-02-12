// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package controllers

import (
	"context"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/template"
)

type ValidatorFunc func(context.Context, client.Object) error

func ValidateSecretTransformation(_ context.Context, o client.Object) error {
	var errs error
	switch t := o.(type) {
	case *v1beta1.SecretTransformation:
		stmpl := template.NewSecretTemplate(t.Name)
		objKey := client.ObjectKeyFromObject(o)
		for idx, tmpl := range t.Spec.SourceTemplates {
			var name string
			if tmpl.Name == "" {
				name = fmt.Sprintf("%s/%d", objKey, idx)
			} else {
				name = fmt.Sprintf("%s/%s", objKey, name)
			}
			if err := stmpl.Parse(name, tmpl.Text); err != nil {
				errs = errors.Join(errs, err)
			}
		}

		for name, tmpl := range t.Spec.Templates {
			if tmpl.Name != "" {
				name = tmpl.Name
			}

			name = fmt.Sprintf("%s/%s", objKey, name)
			if err := stmpl.Parse(name, tmpl.Text); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	default:
		errs = errors.Join(errs, fmt.Errorf(
			"unsupported type %T", t))
	}
	return errs
}
