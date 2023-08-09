// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
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
	return ownerRef, nil
}
