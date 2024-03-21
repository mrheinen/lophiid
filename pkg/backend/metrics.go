package backend

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type BackendMetrics struct {
	reqsQueueGauge        prometheus.Gauge
	rpcResponseTime       prometheus.Histogram
	reqsQueueResponseTime prometheus.Histogram
	whoisResponseTime     prometheus.Histogram
	downloadResponseTime  prometheus.Histogram
	qRunnerResponseTime   prometheus.Histogram
	honeypotRequests      *prometheus.CounterVec
	methodPerRequest      *prometheus.CounterVec
	requestsPerPort       *prometheus.CounterVec
}

// Register Metrics
func CreateBackendMetrics(reg prometheus.Registerer) *BackendMetrics {

	m := &BackendMetrics{
		reqsQueueGauge:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "backend_requests_queue", Help: "The amount of requests in the requests queue"}),
		rpcResponseTime:       prometheus.NewHistogram(prometheus.HistogramOpts{Name: "backend_full_rpc_response_time", Help: "Response time for backend rpcs", Buckets: metrics.FastResponseTimebuckets}),
		reqsQueueResponseTime: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "backend_full_reqs_queue_response_time", Help: "Response time for processing the request queue", Buckets: metrics.MediumResponseTimebuckets}),
		whoisResponseTime:     prometheus.NewHistogram(prometheus.HistogramOpts{Name: "backend_full_whois_response_time", Help: "Response time for whois lookups", Buckets: metrics.MediumResponseTimebuckets}),
		downloadResponseTime:  prometheus.NewHistogram(prometheus.HistogramOpts{Name: "backend_full_download_response_time", Help: "Total time for downloads", Buckets: metrics.SlowResponseTimebuckets}),
		qRunnerResponseTime:   prometheus.NewHistogram(prometheus.HistogramOpts{Name: "backend_full_query_runner_response_time", Help: "Total time for the query runner", Buckets: metrics.SlowResponseTimebuckets}),
		honeypotRequests:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "backend_honeypot_requests_total", Help: "How HTTP requests honeypots get"}, []string{"ip"}),
		methodPerRequest:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "backend_request_method_total", Help: "Amount of requests per HTTP method"}, []string{"method"}),
		requestsPerPort:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "backend_request_per_port_total", Help: "Amount of requests per HTTP port"}, []string{"port"}),
	}

	reg.MustRegister(m.reqsQueueGauge)
	reg.MustRegister(m.rpcResponseTime)
	reg.MustRegister(m.reqsQueueResponseTime)
	reg.MustRegister(m.whoisResponseTime)
	reg.MustRegister(m.downloadResponseTime)
	reg.MustRegister(m.honeypotRequests)
	reg.MustRegister(m.qRunnerResponseTime)
	reg.MustRegister(m.methodPerRequest)
	reg.MustRegister(m.requestsPerPort)
	return m
}
