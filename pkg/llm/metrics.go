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
package llm

import (
	"lophiid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type LLMMetrics struct {
	llmQueryResponseTime prometheus.Histogram
	llmErrorCount        prometheus.Counter
	llmCacheHits         *prometheus.CounterVec
}

// Register Metrics
func CreateLLMMetrics(reg prometheus.Registerer) *LLMMetrics {
	m := &LLMMetrics{
		llmQueryResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_backend_llm_complete_response_time",
				Help:    "Response time for successful LLM completion requests",
				Buckets: metrics.MediumResponseTimebuckets},
		),
		llmErrorCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "lophiid_backend_llm_error_count",
				Help: "Total LLM comunication errors",
			}),
		llmCacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_backend_llm_cache_hits",
				Help: "How many cache hits the first triage has"},
			[]string{"result"}),
	}

	reg.MustRegister(m.llmCacheHits)
	reg.MustRegister(m.llmQueryResponseTime)
	reg.MustRegister(m.llmErrorCount)
	return m
}
