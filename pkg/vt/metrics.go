package vt

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type VTMetrics struct {
	fileSubmitResponseTime prometheus.Histogram
	urlSubmitResponseTime  prometheus.Histogram
	analysisResponseTime   prometheus.Histogram
	apiCallsCount          *prometheus.CounterVec
}

// Register Metrics
func CreateVTMetrics(reg prometheus.Registerer) *VTMetrics {
	m := &VTMetrics{
		fileSubmitResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_vt_submit_file_duration",
				Help:    "Submit file API duration",
				Buckets: metrics.MediumResponseTimebuckets}),
		urlSubmitResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_vt_submit_url_duration",
				Help:    "Submit URL duration",
				Buckets: metrics.MediumResponseTimebuckets}),
		analysisResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_vt_get_analysis_duration",
				Help:    "Duration of fetching analysis results",
				Buckets: metrics.MediumResponseTimebuckets}),
		apiCallsCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_vt_ip_calls_per_api_count",
				Help: "Amount of calls per API"}, []string{"api"}),
	}

	reg.MustRegister(m.fileSubmitResponseTime)
	reg.MustRegister(m.urlSubmitResponseTime)
	reg.MustRegister(m.analysisResponseTime)
	reg.MustRegister(m.apiCallsCount)
	return m
}
