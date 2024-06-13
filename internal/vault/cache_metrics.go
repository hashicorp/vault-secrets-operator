// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const (
	subsystemClientCache      = "client_cache"
	subsystemClientCloneCache = "client_clone_cache"
)

var (

	// metricsFQNClientCacheSize for the ClientCache.
	metricsFQNClientCacheSize = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, "size")

	// metricsFQNClientCacheLength for the ClientCache.
	metricsFQNClientCacheLength = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, metrics.NameLength)

	// metricsFQNClientCacheHits for the ClientCache.
	metricsFQNClientCacheHits = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, "hits")

	// metricsFQNClientCacheMisses for the ClientCache.
	metricsFQNClientCacheMisses = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, "misses")

	// metricsFQNClientCacheEvictions for the ClientCache.
	metricsFQNClientCacheEvictions = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, "evictions")

	// metricsFQNClientCloneCacheHits for the ClientCache.
	metricsFQNClientCloneCacheHits = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCloneCache, "hits")

	// metricsFQNClientCloneCacheMisses for the ClientCache.
	metricsFQNClientCloneCacheMisses = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCloneCache, "misses")

	// metricsFQNClientCacheEvictions for the ClientCache.
	metricsFQNClientCloneCacheEvictions = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCloneCache, "evictions")

	// metricsFQNClientCacheTaintedClients for the ClientCache.
	metricsFQNClientCacheTaintedClients = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, metrics.NameTainted)

	// metricsFQNClientCacheClientRefs for the ClientCache.
	metricsFQNClientCacheClientRefs = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientCache, metrics.NameClientRefs)
)

var _ prometheus.Collector = (*clientCacheCollector)(nil)

// clientCacheCollector provides a prometheus.Collector for ClientCache metrics.
type clientCacheCollector struct {
	cache       ClientCache
	size        float64
	sizeDesc    *prometheus.Desc
	lenDesc     *prometheus.Desc
	taintedDesc *prometheus.Desc
	refsDesc    *prometheus.Desc
}

func (c clientCacheCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sizeDesc
	ch <- c.lenDesc
	ch <- c.taintedDesc
	ch <- c.refsDesc
}

func (c clientCacheCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.cache.Stats()
	ch <- prometheus.MustNewConstMetric(c.sizeDesc, prometheus.GaugeValue, c.size)
	ch <- prometheus.MustNewConstMetric(c.lenDesc, prometheus.GaugeValue, float64(stats.Len))
	ch <- prometheus.MustNewConstMetric(c.taintedDesc, prometheus.GaugeValue, float64(stats.Tainted))
	ch <- prometheus.MustNewConstMetric(c.refsDesc, prometheus.GaugeValue, float64(stats.Refs))
}

func newClientCacheCollector(cache ClientCache, size int) prometheus.Collector {
	return &clientCacheCollector{
		cache: cache,
		size:  float64(size),
		sizeDesc: prometheus.NewDesc(
			metricsFQNClientCacheSize,
			"Size of the cache.",
			nil, nil),
		lenDesc: prometheus.NewDesc(
			metricsFQNClientCacheLength,
			"Number of Vault Clients in the cache.",
			nil, nil),
		taintedDesc: prometheus.NewDesc(
			metricsFQNClientCacheTaintedClients,
			"Number of tainted Vault Clients in the cache.",
			nil, nil),
		refsDesc: prometheus.NewDesc(
			metricsFQNClientCacheClientRefs,
			"Total number of client object references.",
			nil, nil),
	}
}
