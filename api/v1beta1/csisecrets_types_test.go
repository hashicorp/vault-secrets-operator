// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package v1beta1

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

func TestCSISecretsDefaultModeValidation(t *testing.T) {
	for _, dir := range []string{"config/crd/bases", "chart/crds"} {
		t.Run(dir, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", dir, "secrets.hashicorp.com_csisecrets.yaml"))
			require.NoError(t, err)
			var crd apiextensionsv1.CustomResourceDefinition
			require.NoError(t, yaml.Unmarshal(data, &crd))
			require.NotEmpty(t, crd.Spec.Versions)

			for _, version := range crd.Spec.Versions {
				t.Run(version.Name, func(t *testing.T) {
					require.NotNil(t, version.Schema)
					require.NotNil(t, version.Schema.OpenAPIV3Schema)
					spec := version.Schema.OpenAPIV3Schema.Properties["spec"]
					var schema apiextensions.JSONSchemaProps
					require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(&spec, &schema, nil))
					structural, err := structuralschema.NewStructural(&schema)
					require.NoError(t, err)
					celValidator := cel.NewValidator(structural, false, celconfig.PerCallLimit)
					require.NotNil(t, celValidator)
					schemaValidator, _, err := validation.NewSchemaValidator(&schema)
					require.NoError(t, err)

					object := func(mode *int64) map[string]interface{} {
						obj := map[string]interface{}{
							"accessControl": map[string]interface{}{"serviceAccountPattern": "default"},
							"secrets":       map[string]interface{}{},
						}
						if mode != nil {
							obj["defaultMode"] = *mode
						}
						return obj
					}
					validate := func(obj, oldObj map[string]interface{}) field.ErrorList {
						errs := validation.ValidateCustomResource(field.NewPath("spec"), obj, schemaValidator)
						celErrs, _ := celValidator.Validate(context.Background(), field.NewPath("spec"), structural, obj, oldObj, celconfig.RuntimeCELCostBudget)
						return append(errs, celErrs...)
					}

					defaultMode := int64(0o440)
					for _, update := range []bool{false, true} {
						t.Run(fmt.Sprintf("update=%t", update), func(t *testing.T) {
							var oldObj map[string]interface{}
							if update {
								oldObj = object(&defaultMode)
							}
							require.Empty(t, validate(object(nil), oldObj), "omitting defaultMode must remain valid")
							// Exercise every permission combination, plus the range boundaries.
							for mode := int64(-1); mode <= 0o1000; mode++ {
								t.Run(fmt.Sprintf("mode=%04o", mode), func(t *testing.T) {
									errs := validate(object(&mode), oldObj)
									if mode >= 0 && mode <= 0o777 && mode&0o002 == 0 {
										require.Empty(t, errs)
									} else {
										require.NotEmpty(t, errs)
										if mode >= 0 && mode <= 0o777 {
											require.Contains(t, errs.ToAggregate().Error(), "must not grant write permission to others")
										}
									}
								})
							}
						})
					}
				})
			}
		})
	}
}
