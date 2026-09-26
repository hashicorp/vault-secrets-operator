// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	"github.com/hashicorp/vault-secrets-operator/internal/version"
)

var (
	// used for monkey patching tests
	saRootDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	ErrNoCurrentNamespace = errors.New("could not determine current namespace")
)

// GetCurrentNamespace returns the "current" namespace,
// as it is configured in the default service account's namespace file.
// The namespace file should be accessible when running in a cluster.
func GetCurrentNamespace() (string, error) {
	filename := filepath.Join(saRootDir, "namespace")
	b, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoCurrentNamespace, err)
	}

	return string(bytes.Trim(b, " ")), nil
}

func GetOwnerRefFromObj(owner ctrlclient.Object, scheme *runtime.Scheme) (metav1.OwnerReference, error) {
	ownerRef := metav1.OwnerReference{
		Name: owner.GetName(),
		UID:  owner.GetUID(),
	}

	gvk, err := apiutil.GVKForObject(owner, scheme)
	if err != nil {
		return ownerRef, err
	}

	apiVersion, kind := gvk.ToAPIVersionAndKind()
	ownerRef.APIVersion = apiVersion
	ownerRef.Kind = kind
	ownerRef.Controller = ptr.To(true)
	return ownerRef, nil
}

// LoadCRDsFromDir reads dir to find any CustomResourceDefinition YAML manifest
// files. It only supports apiextensionsv1.CustomResourceDefinition. Returns a
// slice of apiextensionsv1.CustomResourceDefinition objects or an error if any
// occurred.
func LoadCRDsFromDir(dir string) ([]apiextensionsv1.CustomResourceDefinition, error) {
	d, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var ret []apiextensionsv1.CustomResourceDefinition
	for _, f := range d {
		if f.IsDir() {
			continue
		}

		if !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}

		fn := filepath.Join(dir, f.Name())
		fh, err := os.Open(fn)
		if err != nil {
			return nil, err
		}

		crds, err := DecodeCRDs(fh)
		if err != nil {
			return nil, err
		}

		ret = append(ret, crds...)
	}

	return ret, nil
}

type empty struct{}

// DecodeCRDs reads input to decode CustomResourceDefinition YAML manifest data.
// It supports multiple YAML documents.
func DecodeCRDs(input io.Reader) ([]apiextensionsv1.CustomResourceDefinition, error) {
	var crds []apiextensionsv1.CustomResourceDefinition
	dec := yamlv3.NewDecoder(input)
	seen := map[string]empty{}
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		b, err := yaml.Marshal(doc)
		if err != nil {
			return nil, err
		}

		jsonB, err := yaml.YAMLToJSONStrict(b)
		if err != nil {
			return nil, err
		}

		var crd apiextensionsv1.CustomResourceDefinition
		if err := json.Unmarshal(jsonB, &crd); err != nil {
			return nil, err
		}

		if crd.GroupVersionKind() != apiextensionsv1.SchemeGroupVersion.WithKind(crd.Kind) {
			continue
		}

		if _, ok := seen[crd.Name]; ok {
			return nil, fmt.Errorf("duplicate CRD %q found", crd.Name)
		}
		seen[crd.Name] = empty{}

		crds = append(crds, crd)
	}
	return crds, nil
}

// UpgradeCRDs upgrades custom resource definitions a directory containing CRD
// YAML manifest files. It only supports
// apiextensionsv1.CustomResourceDefinition. If the CRD exists in the cluster, it
// will be patched from the contents from the corresponding manifest file. If the
// CRD does not exist, it will be created. The Client must have the
// apiextensionsv1.Scheme registered.
func UpgradeCRDs(ctx context.Context, c ctrlclient.Client, dir string) error {
	logger := zap.New().WithName("UpgradeCRDs").WithValues(
		"version", version.Version(), "dir", dir)

	crds, err := LoadCRDsFromDir(dir)
	if err != nil {
		return err
	}

	if len(crds) == 0 {
		return fmt.Errorf("no CRDs found in directory %q", dir)
	}

	// TODO(future): add support for optionally deleting obsolete CRDs
	var errs error
	for _, crd := range crds {
		var cur apiextensionsv1.CustomResourceDefinition
		if err := c.Get(ctx, ctrlclient.ObjectKey{Name: crd.Name}, &cur); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Info("Creating", "name", crd.Name, "gvk", crd.GroupVersionKind())
				if err := c.Create(ctx, &crd); err != nil {
					return err
				}
			} else {
				errs = errors.Join(errs, err)
			}
		} else {
			logger.Info("Patching",
				"name", crd.Name, "gvk", crd.GroupVersionKind(),
				"uid", cur.GetUID(), "resourceVersion", cur.GetResourceVersion(),
			)
			patch := ctrlclient.MergeFrom(cur.DeepCopy())
			cur.Spec = crd.Spec
			cur.ObjectMeta.Annotations = crd.ObjectMeta.Annotations
			cur.ObjectMeta.Labels = crd.ObjectMeta.Labels
			errors.Join(errs, c.Patch(ctx, &cur, patch))
		}
	}

	return errs
}
