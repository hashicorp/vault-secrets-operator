// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hashicorp/vault-secrets-operator/internal/metrics"
)

const (
	subsystemClient = "client"
)

var (

	// TODO: update to use Native Histograms once it is no longer an experimental Prometheus feature
	// ref: https://github.com/prometheus/prometheus/milestone/10
	clientOperationTimes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Subsystem: subsystemClient,
		Name:      metrics.NameOperationsTimeSeconds,
		Buckets: []float64{
			0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.25, 1.5, 1.75, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5, 6, 7, 8, 9, 10,
		},
		Help: "Length of time per Vault client operation",
	}, []string{metrics.LabelOperation, metrics.LabelVaultConnection})

	clientOperations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystemClient,
		Name:        metrics.NameOperationsTotal,
		Help:        "Vault Client successful operations",
		ConstLabels: nil,
	}, []string{metrics.LabelOperation, metrics.LabelVaultConnection})

	clientOperationErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.Namespace,
		Subsystem:   subsystemClient,
		Name:        metrics.NameOperationsErrorsTotal,
		Help:        "Vault Client operation errors",
		ConstLabels: nil,
	}, []string{metrics.LabelOperation, metrics.LabelVaultConnection})
)

// MustRegisterClientMetrics to register the global Client Prometheus metrics.
func MustRegisterClientMetrics(registry prometheus.Registerer) {
	registry.MustRegister(
		clientOperationTimes,
		clientOperations,
		clientOperationErrors,
	)
}
