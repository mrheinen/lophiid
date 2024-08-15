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
//
package vt

import (
	"lophiid/pkg/metrics"

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
