// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package utils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetCurrentNamespace(t *testing.T) {
	tests := []struct {
		name      string
		want      string
		contents  string
		writeFile bool
		fileMode  os.FileMode
		wantErr   bool
	}{
		{
			name:      "basic",
			want:      "baz",
			contents:  "baz",
			writeFile: true,
			fileMode:  0o600,
			wantErr:   false,
		},
		{
			name:      "basic-with-spaces",
			want:      "qux",
			contents:  "  qux ",
			writeFile: true,
			fileMode:  0o600,
			wantErr:   false,
		},
		{
			name:      "error-no-exist",
			writeFile: false,
			wantErr:   true,
		},
		{
			name:      "error-permission-denied",
			writeFile: true,
			fileMode:  0o000,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.writeFile {
				dir := t.TempDir()
				origSARootDir := saRootDir
				t.Cleanup(func() {
					saRootDir = origSARootDir
				})
				saRootDir = dir
				filename := filepath.Join(dir, "namespace")
				if err := os.WriteFile(filename, []byte(tt.contents), tt.fileMode); err != nil {
					t.Fatalf("failed to write namespace file %s, err=%s", filename, err)
				}
			}

			got, err := GetCurrentNamespace()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCurrentNamespace() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetCurrentNamespace() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpgradeCRDs(t *testing.T) {
	t.Parallel()

	manifests := []string{
		`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: hcpauths.secrets.hashicorp.com
spec:
  group: secrets.hashicorp.com
  names:
    kind: HCPAuth
    listKind: HCPAuthList
    plural: hcpauths
    singular: hcpauth
  scope: Namespaced
  versions:
  - name: v1beta1
`,
	}

	manifestsUpdated := []string{
		`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: hcpauths.secrets.hashicorp.com
spec:
  group: secrets.hashicorp.com
  names:
    kind: HCPAuth
    listKind: HCPAuthList
    plural: hcpauths
    singular: hcpauth
  scope: Cluster
  versions:
  - name: v1beta2
`,
	}

	others := []string{
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: foo
`,
	}

	wantCRD := &apiextensionsv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiextensionsv1.SchemeGroupVersion.String(),
			Kind:       "CustomResourceDefinition",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hcpauths.secrets.hashicorp.com",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "secrets.hashicorp.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "HCPAuth",
				ListKind: "HCPAuthList",
				Plural:   "hcpauths",
				Singular: "hcpauth",
			},
			Scope: "Namespaced",
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name: "v1beta1",
				},
			},
		},
	}

	wantCRDUpdated := wantCRD.DeepCopy()
	wantCRDUpdated.Spec.Scope = "Cluster"
	wantCRDUpdated.Spec.Versions = []apiextensionsv1.CustomResourceDefinitionVersion{
		{
			Name: "v1beta2",
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, apiextensionsv1.AddToScheme(scheme))

	root := t.TempDir()
	ctx := context.Background()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	tests := []struct {
		name           string
		c              client.Client
		create         []*apiextensionsv1.CustomResourceDefinition
		createDir      bool
		manifests      []string
		otherManifests []string
		subDirs        int
		canaries       int
		want           []*apiextensionsv1.CustomResourceDefinition
		wantErr        assert.ErrorAssertionFunc
	}{
		{
			name:           "create",
			c:              builder.Build(),
			createDir:      true,
			subDirs:        2,
			canaries:       2,
			otherManifests: others,
			manifests:      manifests,
			want: []*apiextensionsv1.CustomResourceDefinition{
				wantCRD.DeepCopy(),
			},
			wantErr: assert.NoError,
		},
		{
			name:           "upgrade",
			c:              builder.Build(),
			createDir:      true,
			subDirs:        2,
			canaries:       2,
			manifests:      manifestsUpdated,
			otherManifests: others,
			create: []*apiextensionsv1.CustomResourceDefinition{
				wantCRD.DeepCopy(),
			},
			want: []*apiextensionsv1.CustomResourceDefinition{
				wantCRDUpdated.DeepCopy(),
			},
			wantErr: assert.NoError,
		},
		{
			name:      "invalid-scheme-not-registered",
			c:         fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
			createDir: true,
			manifests: manifests,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err,
					"no kind is registered for the type v1.CustomResourceDefinition in scheme")
			},
		},
		{
			name: "invalid-no-dir", wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorIs(t, err, os.ErrNotExist)
			},
		},
		{
			name:           "invalid-no-crds-found",
			otherManifests: others,
			createDir:      true,
			subDirs:        2,
			canaries:       2,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "no CRDs found in directory")
			},
		},
		{
			name:           "invalid-yaml-parse-error",
			otherManifests: []string{"foo:\n-bar"},
			createDir:      true,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, `yaml: line 2: could not find expected ':'`)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(root, tt.name)
			if tt.createDir {
				require.NoError(t, os.MkdirAll(dir, 0o700))
				t.Cleanup(func() {
					require.NoError(t, os.RemoveAll(dir))
				})
			}

			if len(tt.manifests) > 0 || len(tt.otherManifests) > 0 || tt.subDirs > 0 || tt.canaries > 0 {
				require.True(t, tt.createDir, "createDir cannot be false")
			}

			for idx, mft := range tt.otherManifests {
				filename := filepath.Join(dir, fmt.Sprintf("other-%d.yaml", idx))
				require.NoError(t, os.WriteFile(filename, []byte(mft), 0o600))
			}

			for i := 0; i < tt.subDirs; i++ {
				subDir := filepath.Join(dir, fmt.Sprintf("dir-%d", i))
				require.NoError(t, os.Mkdir(subDir, 0o700))
			}

			for i := 0; i < tt.subDirs; i++ {
				filename := filepath.Join(dir, fmt.Sprintf("canary-%d", i))
				require.NoError(t, os.WriteFile(filename, []byte{}, 0o600))
			}

			for idx, mft := range tt.manifests {
				filename := filepath.Join(dir, fmt.Sprintf("manifest-%d.yaml", idx))
				require.NoError(t, os.WriteFile(filename, []byte(mft), 0o600))
			}

			for _, crd := range tt.create {
				require.NoError(t, tt.c.Create(ctx, crd))
			}

			if !tt.wantErr(t, UpgradeCRDs(ctx, tt.c, dir), fmt.Sprintf("UpgradeCRDs(%v, %v, %v)",
				ctx, tt.c, dir)) {
				return
			}

			for _, w := range tt.want {
				var crd apiextensionsv1.CustomResourceDefinition
				require.NoError(t, tt.c.Get(ctx, client.ObjectKey{Name: w.Name}, &crd))
				assert.Equal(t, w.TypeMeta, crd.TypeMeta)
				assert.Equal(t, w.Spec, crd.Spec)
			}
		})
	}
}
