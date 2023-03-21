// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const (
	subsystemClientStorageCache = subsystemClientCache + "_storage"
	metricsOperationStore       = "store"
	metricsOperationRestore     = "restore"
	metricsOperationRestoreAll  = "restore_all"
	metricsOperationPrune       = "prune"
	metricsOperationPurge       = "purge"

	metricsLabelOperation         = "operation"
	metricsLabelEnforceEncryption = "enforce_encryption"
)

// metricsFQNClientCacheStorageLength for the ClientCache.
var (
	metricsFQNClientCacheStorageConfig = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "config")
	metricsFQNClientCacheStorageLength = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "length")
	metricsFQNClientCacheStorageReqsTotal = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "requests_total")
	metricsFQNClientCacheStorageReqsErrorsTotal = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "requests_errors_total")
	metricsFQNClientCacheStorageOpsTotal = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "operations_total")
	metricsFQNClientCacheStorageOpsErrorsTotal = prometheus.BuildFQName(
		metrics.MetricsNamespace, subsystemClientStorageCache, "operations_errors_total")
)

var _ prometheus.Collector = (*clientCacheStorageCollector)(nil)

// clientCacheStorageCollector provides a prometheus.Collector for ClientCacheStorage metrics.
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
