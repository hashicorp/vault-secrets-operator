// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package helpers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// NewSecretsClientForManager creates a new client for interacting with secrets that match
// the given selector. This client is useful to avoid caching all secrets in a
// cluster. The client will cache only secrets that match the selector.
// The ctrl.Manager needs to be started before client can be used.
func NewSecretsClientForManager(ctx context.Context, mgr ctrl.Manager, selector labels.Selector) (ctrlclient.Client, error) {
	if selector.Empty() {
		return nil, fmt.Errorf("selector cannot be empty")
	}

	scheme := mgr.GetScheme()
	httpClient := mgr.GetHTTPClient()
	restMapper := mgr.GetRESTMapper()
	cacheOpts := cache.Options{
		ReaderFailOnMissingInformer: true,
		HTTPClient:                  httpClient,
		Scheme:                      scheme,
		Mapper:                      restMapper,
		ByObject: map[ctrlclient.Object]cache.ByObject{
			&corev1.Secret{}: {
				Label: selector,
			},
		},
	}

	newCache, err := cache.New(mgr.GetConfig(), cacheOpts)
	if err != nil {
		return nil, err
	}

	if _, err := newCache.GetInformer(ctx, &corev1.Secret{}); err != nil {
		return nil, err
	}

	if err := mgr.Add(newCache); err != nil {
		return nil, err
	}

	client, err := ctrlclient.New(mgr.GetConfig(), ctrlclient.Options{
		HTTPClient: httpClient,
		Scheme:     scheme,
		Mapper:     restMapper,
		Cache: &ctrlclient.CacheOptions{
			Reader: newCache,
		},
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}
