// Copyright (c) 2022 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
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
