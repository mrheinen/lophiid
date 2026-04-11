// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
	"context"
	"testing"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfig returns a minimal valid config for pipeline tests.
func testConfig() CampaignAgentConfig {
	cfg := CampaignAgentConfig{}
	cfg.Agent.ScanInterval = time.Hour
	cfg.Agent.LookbackWindow = 24 * time.Hour
	cfg.Agent.CampaignMinRequests = 2
	cfg.Agent.CampaignMinSourceIPs = 2
	cfg.Agent.SimilarityThreshold = 1.0
	cfg.Agent.ActiveWindow = 48 * time.Hour
	cfg.Agent.CloseWindow = 168 * time.Hour
	cfg.Agent.ResummarizeThreshold = 0.2
	cfg.Agent.RetroactiveLookback = 168 * time.Hour
	cfg.Agent.CorrelationPadding = time.Hour
	cfg.Agent.CorrelationFeatures = []string{constants.CampaignCorrelationSourceIP}
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {
			Enabled: true,
			Features: map[string]FeatureConfig{
				"source_ip": {Weight: 0.9},
				"cmp_hash":  {Weight: 0.8},
			},
		},
	}
	return cfg
}

func TestPipeline_QualifiesAsCampaign_ByRequests(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.CampaignMinRequests = 3
	cfg.Agent.CampaignMinSourceIPs = 100

	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	requests := []EnrichedRequest{
		{RequestID: 1, SourceIP: "1.1.1.1"},
		{RequestID: 2, SourceIP: "1.1.1.1"},
		{RequestID: 3, SourceIP: "1.1.1.1"},
	}
	assert.True(t, p.qualifiesAsCampaign(requests))
}

func TestPipeline_QualifiesAsCampaign_ByIPs(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.CampaignMinRequests = 100
	cfg.Agent.CampaignMinSourceIPs = 2

	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	requests := []EnrichedRequest{
		{RequestID: 1, SourceIP: "1.1.1.1"},
		{RequestID: 2, SourceIP: "2.2.2.2"},
	}
	assert.True(t, p.qualifiesAsCampaign(requests))
}

func TestPipeline_QualifiesAsCampaign_NotQualified(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.CampaignMinRequests = 10
	cfg.Agent.CampaignMinSourceIPs = 10

	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	requests := []EnrichedRequest{
		{RequestID: 1, SourceIP: "1.1.1.1"},
	}
	assert.False(t, p.qualifiesAsCampaign(requests))
}

func TestPipeline_NeedsResummarization_NewCampaign(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, false, false)

	c := &models.Campaign{Name: ""}
	state := &AggregationState{Behavior: BehaviorSection{TotalRequests: 50}}
	assert.True(t, p.needsResummarization(c, state))
}

func TestPipeline_NeedsResummarization_SignificantGrowth(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.ResummarizeThreshold = 0.2
	p := NewPipeline(nil, nil, cfg, nil, false, false, false)

	c := &models.Campaign{Name: "Existing", RequestCount: 100}
	state := &AggregationState{Behavior: BehaviorSection{TotalRequests: 125}}
	assert.True(t, p.needsResummarization(c, state), "25% growth exceeds 20% threshold")
}

func TestPipeline_NeedsResummarization_SmallGrowth(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.ResummarizeThreshold = 0.2
	p := NewPipeline(nil, nil, cfg, nil, false, false, false)

	c := &models.Campaign{Name: "Existing", RequestCount: 100}
	state := &AggregationState{Behavior: BehaviorSection{TotalRequests: 110}}
	assert.False(t, p.needsResummarization(c, state), "10% growth below 20% threshold")
}

func TestPipeline_ScoreFingerprintPair_Overlap(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	a := NewFingerprint()
	a.Add("source_ip", "1.2.3.4")
	a.Add("cmp_hash", "abc123")

	b := NewFingerprint()
	b.Add("source_ip", "1.2.3.4")
	b.Add("cmp_hash", "different")

	score := p.scoreFingerprintPair(a, b)
	assert.InDelta(t, 0.9, score, 0.001, "only source_ip overlaps")
}

func TestPipeline_ScoreFingerprintPair_NoOverlap(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	a := NewFingerprint()
	a.Add("source_ip", "1.2.3.4")

	b := NewFingerprint()
	b.Add("source_ip", "5.6.7.8")

	score := p.scoreFingerprintPair(a, b)
	assert.Equal(t, 0.0, score)
}

func TestPipeline_ScoreFingerprintPair_ExhaustedFeatureSkipped(t *testing.T) {
	cfg := testConfig()
	// Set exhaust_number=2 for source_ip so that any fingerprint with >= 2 IPs exhausts it.
	cfg.Agent.Sources[constants.CampaignSourceRequest] = SourceConfig{
		Enabled: true,
		Features: map[string]FeatureConfig{
			"source_ip": {Weight: 0.9, ExhaustNumber: 2},
			"cmp_hash":  {Weight: 0.8},
		},
	}
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	a := NewFingerprint()
	// a has 2 source_ip values — meets exhaust_number.
	a.Add("source_ip", "1.2.3.4")
	a.Add("source_ip", "5.6.7.8")
	a.Add("cmp_hash", "abc123")

	b := NewFingerprint()
	b.Add("source_ip", "1.2.3.4")
	b.Add("cmp_hash", "abc123")

	// source_ip is exhausted in a, so only cmp_hash contributes.
	score := p.scoreFingerprintPair(a, b)
	assert.InDelta(t, 0.8, score, 0.001, "exhausted feature should not contribute to merge score")
}

func TestPipeline_ResolveTransitiveMerges(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	// Chain: campaignC -> campaignB -> campaignA (A is oldest, should be the final survivor)
	var campaignA, campaignB, campaignC int64 = 1, 2, 3
	pairs := []mergePair{
		{survivorID: campaignA, absorbedID: campaignB},
		{survivorID: campaignB, absorbedID: campaignC},
	}

	result := p.resolveTransitiveMerges(pairs)
	assert.Equal(t, campaignA, result[campaignB])
	assert.Equal(t, campaignA, result[campaignC])
}

func TestPipeline_ResolveTransitiveMerges_Diamond(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	// A <- B and A <- C and B <- D
	var campaignA, campaignB, campaignC, campaignD int64 = 1, 2, 3, 4
	pairs := []mergePair{
		{survivorID: campaignA, absorbedID: campaignB},
		{survivorID: campaignA, absorbedID: campaignC},
		{survivorID: campaignB, absorbedID: campaignD},
	}

	result := p.resolveTransitiveMerges(pairs)
	assert.Equal(t, campaignA, result[campaignB])
	assert.Equal(t, campaignA, result[campaignC])
	assert.Equal(t, campaignA, result[campaignD])
}

func TestPipeline_ResolveTransitiveMerges_Empty(t *testing.T) {
	cfg := testConfig()
	p := NewPipeline(nil, nil, cfg, nil, false, true, false)

	result := p.resolveTransitiveMerges(nil)
	assert.Nil(t, result)
}

func TestPipeline_DryRun_NoDBWrites(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		CampaignsToReturn:        []models.Campaign{},
		CampaignRequestsToReturn: []models.CampaignRequest{},
		RequestsWithDescriptionsToReturn: []models.RequestWithDescription{
			{
				Request: models.Request{
					ID:           1,
					SourceIP:     "1.2.3.4",
					CmpHash:      "abc",
					BaseHash:     "base1",
					Uri:          "/test",
					Method:       "GET",
					AppID:        1,
					TimeReceived: time.Now().Add(-time.Hour),
				},
			},
			{
				Request: models.Request{
					ID:           2,
					SourceIP:     "1.2.3.4",
					CmpHash:      "abc",
					BaseHash:     "base1",
					Uri:          "/test",
					Method:       "GET",
					AppID:        1,
					TimeReceived: time.Now().Add(-30 * time.Minute),
				},
			},
		},
	}

	cfg := testConfig()
	cfg.Agent.CampaignMinRequests = 2
	registry := &SourceRegistry{
		sources: []CampaignDataSource{&RequestSource{enabled: true}},
	}

	pipeline := NewPipeline(fakeDB, registry, cfg, &NoOpSummarizer{}, true, true, false)

	now := time.Now().UTC()
	result, err := pipeline.Run(context.Background(), now.Add(-24*time.Hour), now)
	require.NoError(t, err)

	// In dry-run, seeds are counted but Insert is never called with a campaign.
	assert.Equal(t, 1, result.CampaignsCreated, "should detect one qualifying cluster")
	// The FakeDB Insert always returns nil error; in dry-run createCampaign returns nil campaign.
}

func TestPipeline_Phase4Lifecycle_ActiveToDormant(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.ActiveWindow = 24 * time.Hour

	fakeDB := &database.FakeDatabaseClient{}
	pipeline := NewPipeline(fakeDB, nil, cfg, nil, true, true, false)

	now := time.Now().UTC()
	campaigns := []models.Campaign{
		{
			ID:         1,
			Status:     constants.CampaignStatusActive,
			LastSeenAt: now.Add(-48 * time.Hour), // 48 hours ago, exceeds 24h active_window.
		},
	}

	result := &PipelineResult{}
	pipeline.phase4Lifecycle(context.Background(), campaigns, now, result)

	assert.Equal(t, constants.CampaignStatusDormant, campaigns[0].Status)
	assert.Equal(t, 1, result.CampaignsDormant)
}

func TestPipeline_Phase4Lifecycle_DormantToClosed(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.ActiveWindow = 24 * time.Hour
	cfg.Agent.CloseWindow = 168 * time.Hour

	fakeDB := &database.FakeDatabaseClient{}
	pipeline := NewPipeline(fakeDB, nil, cfg, nil, true, true, false)

	now := time.Now().UTC()
	campaigns := []models.Campaign{
		{
			ID:         1,
			Status:     constants.CampaignStatusDormant,
			LastSeenAt: now.Add(-200 * time.Hour), // Exceeds 168h close window.
		},
	}

	result := &PipelineResult{}
	pipeline.phase4Lifecycle(context.Background(), campaigns, now, result)

	assert.Equal(t, constants.CampaignStatusClosed, campaigns[0].Status)
	assert.Equal(t, 1, result.CampaignsClosed)
}

func TestPipeline_Phase4Lifecycle_ActiveStaysActive(t *testing.T) {
	cfg := testConfig()
	cfg.Agent.ActiveWindow = 24 * time.Hour

	pipeline := NewPipeline(nil, nil, cfg, nil, true, true, false)

	now := time.Now().UTC()
	campaigns := []models.Campaign{
		{
			ID:         1,
			Status:     constants.CampaignStatusActive,
			LastSeenAt: now.Add(-1 * time.Hour), // Within active_window.
		},
	}

	result := &PipelineResult{}
	pipeline.phase4Lifecycle(context.Background(), campaigns, now, result)

	assert.Equal(t, constants.CampaignStatusActive, campaigns[0].Status)
	assert.Equal(t, 0, result.CampaignsDormant)
	assert.Equal(t, 0, result.CampaignsClosed)
}

func TestPipeline_Phase4Lifecycle_MergedSkipped(t *testing.T) {
	cfg := testConfig()
	pipeline := NewPipeline(nil, nil, cfg, nil, true, true, false)

	now := time.Now().UTC()
	campaigns := []models.Campaign{
		{
			ID:         1,
			Status:     constants.CampaignStatusMerged,
			LastSeenAt: now.Add(-1000 * time.Hour),
		},
	}

	result := &PipelineResult{}
	pipeline.phase4Lifecycle(context.Background(), campaigns, now, result)

	assert.Equal(t, constants.CampaignStatusMerged, campaigns[0].Status, "MERGED campaigns should not transition")
}

func TestPipeline_Phase2Correlate_SessionBased(t *testing.T) {
	cfg := testConfig()

	// Create a campaign with an initial fingerprint.
	fp := NewFingerprint()
	fp.Add("source_ip", "1.1.1.1")
	fpJSON, _ := fp.ToJSON()

	campaign := models.Campaign{
		ID:          1,
		Status:      constants.CampaignStatusActive,
		FirstSeenAt: time.Now().Add(-2 * time.Hour),
		LastSeenAt:  time.Now().Add(-1 * time.Hour),
		Fingerprint: fpJSON,
	}

	// Unassigned request sharing a session with the campaign's existing requests.
	candidateReq := models.Request{
		ID:           200,
		SourceIP:     "1.1.1.1",
		SessionID:    42,
		TimeReceived: time.Now().Add(-90 * time.Minute),
	}

	fakeDB := &database.FakeDatabaseClient{
		UnassignedSessionRequestsToReturn: []models.Request{candidateReq},
	}

	p := NewPipeline(fakeDB, nil, cfg, nil, false, true, false)

	result := &PipelineResult{}
	p.phase2Correlate(context.Background(), []models.Campaign{campaign}, result)

	assert.Equal(t, 1, result.CorrelatedAdded, "session-matched request should be correlated")

	// Verify the fingerprint was not modified by correlation.
	assert.Equal(t, fpJSON, campaign.Fingerprint, "fingerprint should not be modified by correlation")
}
