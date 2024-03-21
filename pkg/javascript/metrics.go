package javascript

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// labels for the success rate measurements.
const RunSuccess = "success"
const RunFailed = "failed"

type GojaMetrics struct {
	javascriptSuccessExecutionTime prometheus.Histogram
	javascriptSuccessCount         *prometheus.CounterVec
}

// Register Metrics
func CreateGoJaMetrics(reg prometheus.Registerer) *GojaMetrics {
	m := &GojaMetrics{
		javascriptSuccessExecutionTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "javascript_success_runs_execution_time",
				Help:    "Execution time of successful runs",
				Buckets: metrics.FastResponseTimebuckets}),
		javascriptSuccessCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "javascript_success_count",
				Help: "Count of success and error runs"}, []string{"result"}),
	}

	reg.MustRegister(m.javascriptSuccessExecutionTime)
	reg.MustRegister(m.javascriptSuccessCount)
	return m
}
