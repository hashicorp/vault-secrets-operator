// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const (
	subsystemClientFactory = "client_factory"
)

var (
	metricsFQNClientFactoryReqsTotal = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientFactory, metrics.NameRequestsTotal)
	metricsFQNClientFactoryReqsErrorsTotal = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientFactory, metrics.NameRequestsErrorsTotal)

	metricsFQNClientFactoryOpsTimeSeconds = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientFactory, metrics.NameOperationsTimeSeconds)

	metricsFQNClientFactoryTaintedClients = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientFactory, metrics.NameTaintedClients)

	metricsFQNClientRefs = prometheus.BuildFQName(
		metrics.Namespace, subsystemClientFactory, metrics.NameClientRefs)

	// TODO: update to use Native Histograms once it is no longer an experimental Prometheus feature
	// ref: https://github.com/prometheus/prometheus/milestone/10
	clientFactoryOperationTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: metricsFQNClientFactoryOpsTimeSeconds,
		Buckets: []float64{
			0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5, 6, 7, 8, 9, 10,
		},
	}, []string{"component", metrics.LabelOperation})
)
