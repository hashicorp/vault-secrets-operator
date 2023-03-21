// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// MetricsNamespace should be use for all Operator metrics that are not
// provided by the controller-runtime.
const MetricsNamespace = "vso"

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
			Namespace: MetricsNamespace,
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
