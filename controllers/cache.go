// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package controllers

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

type cacheEvictionOption struct {
	filterFunc     cacheFilterFunc
	matchingLabels client.MatchingLabels
}
type cacheFilterFunc func(client.Object, secretsv1alpha1.VaultClientCache) bool

func filterOldCacheRefsForAuth(obj client.Object, cache secretsv1alpha1.VaultClientCache) bool {
	return obj.GetUID() == cache.Spec.VaultAuthUID && obj.GetGeneration() > cache.Spec.VaultAuthGeneration
}

func filterOldCacheRefsForConn(obj client.Object, cache secretsv1alpha1.VaultClientCache) bool {
	return obj.GetUID() == cache.Spec.VaultConnectionUID && obj.GetGeneration() > cache.Spec.VaultConnectionGeneration
}

// evictAllReferences on VaultAuth deletion.
func filterAllCacheRefs(_ client.Object, _ secretsv1alpha1.VaultClientCache) bool {
	return true
}

func evictClientCacheRefs(ctx context.Context, c client.Client, o client.Object, recorder record.EventRecorder, option cacheEvictionOption) ([]string, error) {
	if option.filterFunc == nil {
		return nil, fmt.Errorf("a filterFunc is required")
	}

	caches := &secretsv1alpha1.VaultClientCacheList{}
	if err := c.List(ctx, caches, option.matchingLabels); err != nil {
		recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
			"Failed to list VaultCacheClient resources")
		return nil, err
	}

	var evicted []string
	var err error
	for _, item := range caches.Items {
		if option.filterFunc(o, item) {
			dcObj := item.DeepCopy()
			if err := c.Delete(ctx, dcObj); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				// requires go1.20+
				err = errors.Join(err)
				recorder.Eventf(o, corev1.EventTypeWarning, consts.ReasonK8sClientError,
					"Failed to delete %s, on change to %s", item, o)
				continue
			}
			evicted = append(evicted, client.ObjectKeyFromObject(dcObj).String())
		}
	}

	if len(evicted) > 1 {
		recorder.Eventf(o, corev1.EventTypeNormal, consts.ReasonVaultClientCacheEviction,
			"Evicted %d of %d referent VaultCacheClient resources: %v", len(evicted), len(caches.Items), evicted)
	}

	return evicted, err
}
