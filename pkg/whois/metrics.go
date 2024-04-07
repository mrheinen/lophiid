package whois

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type WhoisMetrics struct {
	whoisLookupResponseTime prometheus.Histogram
}

// Register Metrics
func CreateWhoisMetrics(reg prometheus.Registerer) *WhoisMetrics {
	m := &WhoisMetrics{
		whoisLookupResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_whois_lookup_duration",
				Help:    "Whois lookup duration",
				Buckets: metrics.MediumResponseTimebuckets}),
	}

	reg.MustRegister(m.whoisLookupResponseTime)
	return m
}
