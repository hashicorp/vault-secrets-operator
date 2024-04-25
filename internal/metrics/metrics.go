// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// MetricsNamespace should be used for all Operator metrics that are not
// provided by the controller-runtime.
const (
	Namespace      = "vso"
	LabelOperation = "operation"
	// LabelVaultConnection usually contains the full name of VaultConnection CR.
	// e.g. namespace1/connection1
	LabelVaultConnection = "vault_connection"

	OperationGet     = "get"
	OperationStore   = "store"
	OperationRestore = "restore"
	OperationPrune   = "prune"
	OperationDelete  = "delete"
	OperationPurge   = "purge"
	OperationLogin   = "login"
	OperationRenew   = "renew"
	OperationRead    = "read"
	OperationWrite   = "write"

	NameConfig                = "config"
	NameLength                = "length"
	NameOperationsTotal       = "operations_total"
	NameOperationsErrorsTotal = "operations_errors_total"
	NameOperationsTimeSeconds = "operations_time_seconds"
	NameRequestsTotal         = "requests_total"
	NameRequestsErrorsTotal   = "requests_errors_total"
)

var ResourceStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "controller_resource_status",
	Help: "Status of a resource; a value other than 1 denotes an invalid resource",
}, []string{
	"controller",
	"name",
	"namespace",
})

func init() {
	metrics.Registry.MustRegister(
		ResourceStatus,
	)
}

// SetResourceStatus for the given client.Object. If valid is true, then the
// ResourceStatus gauge will be set 1, else 0.
func SetResourceStatus(controller string, o client.Object, valid bool) {
	g := ResourceStatus.WithLabelValues(controller, o.GetName(), o.GetNamespace())
	if valid {
		g.Set(float64(1))
	} else {
		g.Set(float64(0))
	}
}

// NewBuildInfoGauge provides the Operator's build info as a Prometheus metric.
func NewBuildInfoGauge(info apimachineryversion.Info) prometheus.Gauge {
	metric := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "build",
			Name:      "info",
			Help:      "Vault Secrets Operator build info.",
			ConstLabels: map[string]string{
				"major":          info.Major,
				"minor":          info.Minor,
				"git_version":    info.GitVersion,
				"git_commit":     info.GitCommit,
				"git_tree_state": info.GitTreeState,
				"build_date":     info.BuildDate,
				"go_version":     info.GoVersion,
				"compiler":       info.Compiler,
				"platform":       info.Platform,
			},
		},
	)
	metric.Set(1)

	return metric
}
