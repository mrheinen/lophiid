package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
)

type RatelimiterMetrics struct {
	rateBucketsGauge prometheus.Gauge
}

// Register Metrics
func CreateRatelimiterMetrics(reg prometheus.Registerer) *RatelimiterMetrics {
	m := &RatelimiterMetrics{
		rateBucketsGauge: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "lophiid_backend_ratelimit_buckets_gauge",
				Help: "The amount of active ratelimit buckets"},
		),
	}

	reg.MustRegister(m.rateBucketsGauge)
	return m
}
