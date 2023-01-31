package controllers

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	resourceStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "controller_resource_status",
		Help: "Status of a resource; a value of 1 denotes an invalid resource",
	}, []string{
		"controller",
		"name",
		"namespace",
	})

	o = sync.Once{}
)

func InitCommonMetrics() {
	o.Do(func() {
		metrics.Registry.MustRegister(
			resourceStatus,
		)
	})
}
