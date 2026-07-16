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
	subsystemClientWebsocket  = "client_websocket"
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

	// metricsFQNClientWebsocketConnections is the number of real, active
	// WebSocket connections to Vault across all cached clients.
	metricsFQNClientWebsocketConnections = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientWebsocket, "connections")

	// metricsFQNClientWebsocketSubscribers is the number of subscribers (CRs)
	// multiplexed across all active WebSocket connections.
	metricsFQNClientWebsocketSubscribers = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientWebsocket, "subscribers")
)

var _ prometheus.Collector = (*websocketCollector)(nil)

// websocketCollector provides a prometheus.Collector that reports the number
// of real, active Vault event-subscription WebSocket connections, and the
// number of subscribers (CRs) multiplexed onto them, across all clients
// currently held in the ClientCache. This differs from the per-controller
// eventWatcherRegistry counts, which track CR-level bookkeeping rather than
// the actual underlying WebSocket connections (which are shared/multiplexed
// per Vault client + EventType).
type websocketCollector struct {
	cache          ClientCache
	connDesc       *prometheus.Desc
	subscriberDesc *prometheus.Desc
}

func (c *websocketCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connDesc
	ch <- c.subscriberDesc
}

func (c *websocketCollector) Collect(ch chan<- prometheus.Metric) {
	var conns, subs int
	for _, key := range c.cache.Keys() {
		client, ok := c.cache.Get(key)
		if !ok {
			continue
		}
		conns += client.GetWebSocketCount()
		subs += client.GetWebSocketSubscriberCount()
	}
	ch <- prometheus.MustNewConstMetric(c.connDesc, prometheus.GaugeValue, float64(conns))
	ch <- prometheus.MustNewConstMetric(c.subscriberDesc, prometheus.GaugeValue, float64(subs))
}

// newWebsocketCollector returns a prometheus.Collector for real WebSocket
// connection metrics, computed across all clients in the ClientCache.
func newWebsocketCollector(cache ClientCache) prometheus.Collector {
	return &websocketCollector{
		cache: cache,
		connDesc: prometheus.NewDesc(
			metricsFQNClientWebsocketConnections,
			"Number of active, real WebSocket connections to Vault across all cached clients.",
			nil, nil),
		subscriberDesc: prometheus.NewDesc(
			metricsFQNClientWebsocketSubscribers,
			"Number of subscribers (CRs) multiplexed across all active WebSocket connections.",
			nil, nil),
	}
}

var _ prometheus.Collector = (*clientCacheCollector)(nil)

// clientCacheCollector provides a prometheus.Collector for ClientCache metrics.
type clientCacheCollector struct {
	cache    ClientCache
	size     float64
	sizeDesc *prometheus.Desc
	lenDesc  *prometheus.Desc
}

func (c clientCacheCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sizeDesc
	ch <- c.lenDesc
}

func (c clientCacheCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.sizeDesc, prometheus.GaugeValue, c.size)
	ch <- prometheus.MustNewConstMetric(c.lenDesc, prometheus.GaugeValue, float64(c.cache.Len()))
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
	}
}
