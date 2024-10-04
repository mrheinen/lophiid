// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package backend

import (
	"lophiid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	RatelimiterRejectReasonWindow = "window"
	RatelimiterRejectReasonBucket = "bucket"
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
	rateLimiterRejects        *prometheus.CounterVec
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
		rateLimiterRejects: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_backend_rate_limiter_rejects_total",
				Help: "Amount of rejects per type (window or bucket)"},
			[]string{"type"}),
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
	reg.MustRegister(m.rateLimiterRejects)
	return m
}
