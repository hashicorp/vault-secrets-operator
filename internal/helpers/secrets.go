// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package helpers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewSecretWithOwnerRefs(key client.ObjectKey, ownerRefs ...metav1.OwnerReference) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            key.Name,
			Namespace:       key.Namespace,
			OwnerReferences: ownerRefs,
		},
	}
}

func ObjectIsOwnedBy(obj, by client.Object) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == by.GetUID() {
			return true
		}
	}
	return false
}
