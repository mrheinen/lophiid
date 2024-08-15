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
package whois

import (
	"lophiid/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

type WhoisMetrics struct {
	whoisLookupResponseTime   prometheus.Histogram
	whoisRetriesCount         prometheus.Counter
	whoisRetriesExceededCount prometheus.Counter
}

// Register Metrics
func CreateWhoisMetrics(reg prometheus.Registerer) *WhoisMetrics {
	m := &WhoisMetrics{
		whoisLookupResponseTime: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "lophiid_whois_lookup_duration",
				Help:    "Whois lookup duration",
				Buckets: metrics.MediumResponseTimebuckets}),
		whoisRetriesCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "lophiid_whois_total_retries_counter",
				Help: "Total whois retries counter",
			}),
		whoisRetriesExceededCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "lophiid_whois_total_retries_exceeded_counter",
				Help: "Total whois retries exceeded counter",
			}),
	}

	reg.MustRegister(m.whoisLookupResponseTime)
	reg.MustRegister(m.whoisRetriesCount)
	reg.MustRegister(m.whoisRetriesExceededCount)
	return m
}
