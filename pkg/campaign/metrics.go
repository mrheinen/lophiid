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
package campaign

import "github.com/prometheus/client_golang/prometheus"

// PipelineMetrics holds Prometheus metrics for the campaign agent pipeline.
type PipelineMetrics struct {
	CampaignTransitions *prometheus.CounterVec
	RequestsProcessed   prometheus.Counter
	SeedsAdded          prometheus.Counter
	CorrelatedAdded     prometheus.Counter
	LLMCalls            prometheus.Counter
	PipelineErrors      prometheus.Counter
	PipelineRunSeconds  prometheus.Histogram
}

// NewPipelineMetrics creates and registers all campaign pipeline metrics.
func NewPipelineMetrics(reg prometheus.Registerer) *PipelineMetrics {
	m := &PipelineMetrics{
		CampaignTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "campaign_agent_campaign_transitions_total",
			Help: "Total number of campaign transitions by type",
		}, []string{"type"}),
		RequestsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaign_agent_requests_processed_total",
			Help: "Total number of requests processed by the pipeline",
		}),
		SeedsAdded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaign_agent_seeds_added_total",
			Help: "Total number of seed requests added to campaigns",
		}),
		CorrelatedAdded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaign_agent_correlated_added_total",
			Help: "Total number of correlated requests added to campaigns",
		}),
		LLMCalls: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaign_agent_llm_calls_total",
			Help: "Total number of LLM summarization calls",
		}),
		PipelineErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "campaign_agent_pipeline_errors_total",
			Help: "Total number of pipeline errors",
		}),
		PipelineRunSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "campaign_agent_pipeline_run_seconds",
			Help:    "Duration of pipeline runs in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		}),
	}

	reg.MustRegister(
		m.CampaignTransitions,
		m.RequestsProcessed,
		m.SeedsAdded,
		m.CorrelatedAdded,
		m.LLMCalls,
		m.PipelineErrors,
		m.PipelineRunSeconds,
	)

	return m
}

// RecordResult updates metrics from a PipelineResult.
func (m *PipelineMetrics) RecordResult(result *PipelineResult) {
	m.CampaignTransitions.WithLabelValues("created").Add(float64(result.CampaignsCreated))
	m.CampaignTransitions.WithLabelValues("updated").Add(float64(result.CampaignsUpdated))
	m.CampaignTransitions.WithLabelValues("merged").Add(float64(result.CampaignsMerged))
	m.CampaignTransitions.WithLabelValues("dormant").Add(float64(result.CampaignsDormant))
	m.CampaignTransitions.WithLabelValues("closed").Add(float64(result.CampaignsClosed))
	m.RequestsProcessed.Add(float64(result.RequestsProcessed))
	m.SeedsAdded.Add(float64(result.SeedsAdded))
	m.CorrelatedAdded.Add(float64(result.CorrelatedAdded))
	m.LLMCalls.Add(float64(result.LLMCalls))
	m.PipelineErrors.Add(float64(len(result.Errors)))
}
