// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const subsystemClientStorageCache = subsystemClientCache + "_storage"

// metricsFQNClientCacheStorageLength for the ClientCache.
var metricsFQNClientCacheStorageLength = prometheus.BuildFQName(
	metricsNamespace, subsystemClientStorageCache, "length")

var _ prometheus.Collector = (*clientCacheCollector)(nil)

// clientCacheCollector provides a prometheus.Collector for ClientCacheStorage metrics.
type clientCacheStorageCollector struct {
	storage ClientCacheStorage
	ctx     context.Context
	client  ctrlclient.Client
	lenDesc *prometheus.Desc
}

func (c clientCacheStorageCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lenDesc
}

func (c clientCacheStorageCollector) Collect(ch chan<- prometheus.Metric) {
	count, err := c.storage.Len(c.ctx, c.client)
	if err != nil {
		// setting the value to -1 denotes an error occurred checking the storage length
		count = -1
	}
	ch <- prometheus.MustNewConstMetric(c.lenDesc, prometheus.GaugeValue, float64(count))
}

func newClientCacheStorageCollector(cacheStorage ClientCacheStorage, ctx context.Context, client ctrlclient.Client) prometheus.Collector {
	return &clientCacheStorageCollector{
		ctx:     ctx,
		client:  client,
		storage: cacheStorage,
		lenDesc: prometheus.NewDesc(
			metricsFQNClientCacheStorageLength,
			"Number of Vault Clients in the storage cache.",
			nil, nil),
	}
}
