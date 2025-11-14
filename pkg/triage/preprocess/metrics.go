// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
package preprocess

import (
	"lophiid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type PreprocessMetrics struct {
	totalFullPreprocessTime    prometheus.Histogram
	payloadLLMResponseTime     prometheus.Histogram
	shellLLMResponseTime       prometheus.Histogram
	codeEmuLLMResponseTime     prometheus.Histogram
	resultOfPayloadLLMRequests *prometheus.CounterVec
}

func CreatePreprocessMetrics(reg prometheus.Registerer) *PreprocessMetrics {
	m := &PreprocessMetrics{
		payloadLLMResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_triage_preprocess_payload_llm_response_time",
				Help:    "The response time of the payload LLM (success only)",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		shellLLMResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_triage_preprocess_shell_llm_response_time",
				Help:    "The response time of the shell LLM (success only)",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		codeEmuLLMResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_triage_preprocess_code_emu_llm_response_time",
				Help:    "The response time of the code emu LLM (success only)",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		totalFullPreprocessTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_triage_preprocess_payload_total_response_time",
				Help:    "The response time of the preprocess function",
				Buckets: metrics.SlowResponseTimebuckets},
		),
		resultOfPayloadLLMRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "lophiid_triage_preprocess_payload_llm_requests_result_count",
				Help: "The counters of the result of the payload LLM requests"},
			[]string{"result"}),
	}

	reg.MustRegister(m.payloadLLMResponseTime)
	reg.MustRegister(m.shellLLMResponseTime)
	reg.MustRegister(m.codeEmuLLMResponseTime)
	reg.MustRegister(m.totalFullPreprocessTime)
	reg.MustRegister(m.resultOfPayloadLLMRequests)
	return m
}
