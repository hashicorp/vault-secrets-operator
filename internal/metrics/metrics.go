package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var ResourceStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "controller_resource_status",
	Help: "Status of a resource; a value of 1 denotes an invalid resource",
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
