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

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewPipelineMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPipelineMetrics(reg)
	assert.NotNil(t, m)
	assert.NotNil(t, m.CampaignTransitions)
	assert.NotNil(t, m.PipelineRunSeconds)
}

func TestPipelineMetrics_RecordResult(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPipelineMetrics(reg)

	result := &PipelineResult{
		CampaignsCreated:  2,
		CampaignsUpdated:  3,
		CampaignsMerged:   1,
		CampaignsDormant:  1,
		CampaignsClosed:   0,
		RequestsProcessed: 100,
		SeedsAdded:        50,
		CorrelatedAdded:   30,
		LLMCalls:          2,
		Errors:            []error{errors.New("test error")},
	}

	m.RecordResult(result)

	assert.Equal(t, float64(2), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("created")))
	assert.Equal(t, float64(3), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("updated")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("merged")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("dormant")))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("closed")))
	assert.Equal(t, float64(100), testutil.ToFloat64(m.RequestsProcessed))
	assert.Equal(t, float64(50), testutil.ToFloat64(m.SeedsAdded))
	assert.Equal(t, float64(30), testutil.ToFloat64(m.CorrelatedAdded))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.LLMCalls))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.PipelineErrors))
}

func TestPipelineMetrics_RecordResultAccumulates(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPipelineMetrics(reg)

	r1 := &PipelineResult{CampaignsCreated: 2, SeedsAdded: 10}
	r2 := &PipelineResult{CampaignsCreated: 3, SeedsAdded: 20}

	m.RecordResult(r1)
	m.RecordResult(r2)

	assert.Equal(t, float64(5), testutil.ToFloat64(m.CampaignTransitions.WithLabelValues("created")))
	assert.Equal(t, float64(30), testutil.ToFloat64(m.SeedsAdded))
}
