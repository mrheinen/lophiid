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
package describer

import (
	"lophiid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type DescriberMetrics struct {
	pendingRequestsGauge         prometheus.Gauge
	completeMultipleResponsetime prometheus.Histogram
}

func CreateDescriberMetrics(reg prometheus.Registerer) *DescriberMetrics {
	m := &DescriberMetrics{
		pendingRequestsGauge: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "lophiid_describer_pending_requests_gauge",
				Help: "The amount of requests/cmp hashes that need to be described "},
		),
		completeMultipleResponsetime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_describer_complete_multipe_response_time",
				Help:    "Response times of the CompleteMultiple LLM calls",
				Buckets: metrics.SlowResponseTimebuckets},
		),
	}

	reg.MustRegister(m.pendingRequestsGauge)
	reg.MustRegister(m.completeMultipleResponsetime)
	return m
}
