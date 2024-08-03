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
package javascript

import (
	"loophid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// labels for the success rate measurements.
const RunSuccess = "success"
const RunFailed = "failed"

type GojaMetrics struct {
	javascriptSuccessExecutionTime prometheus.Histogram
	javascriptSuccessCount         *prometheus.CounterVec
}

// Register Metrics
func CreateGoJaMetrics(reg prometheus.Registerer) *GojaMetrics {
	m := &GojaMetrics{
		javascriptSuccessExecutionTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "javascript_success_runs_execution_time",
				Help:    "Execution time of successful runs",
				Buckets: metrics.FastResponseTimebuckets}),
		javascriptSuccessCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "javascript_success_count",
				Help: "Count of success and error runs"}, []string{"result"}),
	}

	reg.MustRegister(m.javascriptSuccessExecutionTime)
	reg.MustRegister(m.javascriptSuccessCount)
	return m
}
