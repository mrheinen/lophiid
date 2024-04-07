package backend

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type BackendMetrics struct {
	reqsQueueGauge            prometheus.Gauge
	rpcResponseTime           prometheus.Histogram
	fileUploadRpcResponseTime prometheus.Histogram
	reqsQueueResponseTime     prometheus.Histogram
	downloadResponseTime      prometheus.Histogram
	qRunnerResponseTime       prometheus.Histogram
	honeypotRequests          *prometheus.CounterVec
	methodPerRequest          *prometheus.CounterVec
	requestsPerPort           *prometheus.CounterVec
}

// Register Metrics
func CreateBackendMetrics(reg prometheus.Registerer) *BackendMetrics {

	m := &BackendMetrics{
		reqsQueueGauge: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "lophiid_backend_requests_queue",
				Help: "The amount of requests in the requests queue"},
		),
		rpcResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_full_rpc_response_time",
				Help:    "Response time for backend rpcs",
				Buckets: metrics.FastResponseTimebuckets},
		),
		fileUploadRpcResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_full_file_upload_rpc_response_time",
				Help:    "Response time for backend file upload RPC",
				Buckets: metrics.FastResponseTimebuckets},
		),
		reqsQueueResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_full_reqs_queue_response_time",
				Help:    "Response time for processing the request queue",
				Buckets: metrics.MediumResponseTimebuckets},
		),
		downloadResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_agent_reported_download_response_time",
				Help:    "Total time for downloads",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		qRunnerResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_full_query_runner_response_time",
				Help:    "Total time for the query runner",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		honeypotRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_backend_honeypot_requests_total",
				Help: "How HTTP requests honeypots get"},
			[]string{"ip"},
		),
		methodPerRequest: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_backend_request_method_total",
				Help: "Amount of requests per HTTP method"},
			[]string{"method"},
		),
		requestsPerPort: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_backend_request_per_port_total",
				Help: "Amount of requests per HTTP port"},
			[]string{"port"}),
	}

	reg.MustRegister(m.reqsQueueGauge)
	reg.MustRegister(m.rpcResponseTime)
	reg.MustRegister(m.reqsQueueResponseTime)
	reg.MustRegister(m.downloadResponseTime)
	reg.MustRegister(m.honeypotRequests)
	reg.MustRegister(m.qRunnerResponseTime)
	reg.MustRegister(m.methodPerRequest)
	reg.MustRegister(m.requestsPerPort)
	reg.MustRegister(m.fileUploadRpcResponseTime)
	return m
}
