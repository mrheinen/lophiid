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
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
	whoisPkg "lophiid/pkg/whois"
)

const (
	// MaxCampaignsToSearch is the upper bound on campaigns returned by search queries.
	MaxCampaignsToSearch = 10000
	// MaxRetroactiveRequestsToFetch is the upper bound on requests returned by retroactive lookback queries.
	MaxRetroactiveRequestsToFetch = 50000
	// MaxRequestsToCorrelate is the upper bound on requests returned by correlation queries.
	MaxRequestsToCorrelate = 100000
)

// mergePair represents a merge candidate where the survivor absorbs the other.
type mergePair struct {
	survivorID int64
	absorbedID int64
}

// PipelineResult holds the summary of a single pipeline run.
type PipelineResult struct {
	CampaignsCreated  int
	CampaignsUpdated  int
	CampaignsMerged   int
	CampaignsDormant  int
	CampaignsClosed   int
	RequestsProcessed int
	SeedsAdded        int
	CorrelatedAdded   int
	LLMCalls          int
	Errors            []error
}

// Pipeline orchestrates all phases of a single campaign agent run.
type Pipeline struct {
	db          database.DatabaseClient
	registry    *SourceRegistry
	weights     WeightMap
	correlators []Correlator
	cfg         CampaignAgentConfig
	summarizer  Summarizer
	dryRun      bool
	skipLLM     bool
	backfill    bool
}

// NewPipeline creates a new Pipeline with the given dependencies.
func NewPipeline(db database.DatabaseClient, registry *SourceRegistry, cfg CampaignAgentConfig, summarizer Summarizer, dryRun, skipLLM, backfill bool) *Pipeline {
	return &Pipeline{
		db:          db,
		registry:    registry,
		weights:     BuildWeightMap(cfg.Agent.Sources),
		correlators: BuildCorrelators(cfg.Agent.CorrelationFeatures),
		cfg:         cfg,
		summarizer:  summarizer,
		dryRun:      dryRun,
		skipLLM:     skipLLM,
		backfill:    backfill,
	}
}

// Run executes the full pipeline for the given data window.
func (p *Pipeline) Run(ctx context.Context, windowStart, windowEnd time.Time) (*PipelineResult, error) {
	result := &PipelineResult{}

	slog.Info("pipeline run starting",
		slog.Time("window_start", windowStart),
		slog.Time("window_end", windowEnd),
		slog.Bool("dry_run", p.dryRun),
		slog.Bool("skip_llm", p.skipLLM),
	)

	// Step 1: Load active/dormant campaigns.
	activeCampaigns, err := p.loadActiveCampaigns()
	if err != nil {
		return nil, fmt.Errorf("loading active campaigns: %w", err)
	}
	slog.Info("loaded active campaigns", slog.Int("count", len(activeCampaigns)))

	// Parse fingerprints.
	fingerprints := make(map[int64]Fingerprint)
	for _, c := range activeCampaigns {
		fp, err := FingerprintFromJSON(c.Fingerprint)
		if err != nil {
			slog.Warn("failed to parse fingerprint", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			continue
		}
		fingerprints[c.ID] = fp
	}

	// Preload all enabled data sources for the full time window (including
	// retroactive lookback) so that EnrichRequest reads from in-memory caches
	// instead of issuing per-request database queries.
	preloadStart := windowStart.Add(-p.cfg.Agent.RetroactiveLookback)
	p.registry.PreloadAll(ctx, preloadStart, windowEnd)

	// Phase 1: Seed from malicious requests.
	newCampaigns, modifiedCampaignIDs, err := p.phase1Seed(ctx, windowStart, windowEnd, activeCampaigns, fingerprints, result)
	if err != nil {
		return result, fmt.Errorf("phase 1 (seed): %w", err)
	}

	slog.Info("new campaigns", slog.Int("count", len(newCampaigns)))

	// Retroactive lookback for newly created campaigns.
	if !p.backfill && len(newCampaigns) > 0 {
		p.retroactiveLookback(ctx, windowStart, newCampaigns, fingerprints, result)
	}

	// Combine active + new for subsequent phases.
	allActive := append(activeCampaigns, newCampaigns...)
	for _, c := range newCampaigns {
		modifiedCampaignIDs[c.ID] = true
	}

	// Phase 2: Correlate non-malicious requests.
	p.phase2Correlate(ctx, allActive, result)

	// Phase 3: Campaign merging.
	p.phase3Merge(ctx, allActive, fingerprints, modifiedCampaignIDs, result)

	// Phase 4a: Aggregation state computation.
	// Phase 4b: LLM summarization.
	// Phase 4c: Lifecycle transitions.
	p.phase4Summarize(ctx, allActive, result)
	p.phase4Lifecycle(ctx, allActive, windowEnd, result)

	slog.Info("pipeline run complete",
		slog.Int("campaigns_created", result.CampaignsCreated),
		slog.Int("campaigns_updated", result.CampaignsUpdated),
		slog.Int("campaigns_merged", result.CampaignsMerged),
		slog.Int("seeds_added", result.SeedsAdded),
		slog.Int("correlated_added", result.CorrelatedAdded),
	)

	return result, nil
}

// loadActiveCampaigns loads all ACTIVE and DORMANT campaigns.
func (p *Pipeline) loadActiveCampaigns() ([]models.Campaign, error) {
	// TODO: consider updating this to: status:ACTIVE OR status:DORMANT
	active, err := p.db.SearchCampaigns(0, MaxCampaignsToSearch, "status:"+constants.CampaignStatusActive)
	if err != nil {
		return nil, err
	}
	dormant, err := p.db.SearchCampaigns(0, MaxCampaignsToSearch, "status:"+constants.CampaignStatusDormant)
	if err != nil {
		return nil, err
	}
	return append(active, dormant...), nil
}

// phase1Seed implements Phase 1: seed from malicious requests.
// Returns newly created campaigns, set of modified campaign IDs, and error.
func (p *Pipeline) phase1Seed(ctx context.Context, windowStart, windowEnd time.Time, activeCampaigns []models.Campaign, fingerprints map[int64]Fingerprint, result *PipelineResult) ([]models.Campaign, map[int64]bool, error) {
	modifiedIDs := make(map[int64]bool)

	// Query unassigned malicious requests in the window.
	candidates, err := p.fetchMaliciousCandidates(windowStart, windowEnd)
	if err != nil {
		return nil, modifiedIDs, fmt.Errorf("fetching malicious candidates: %w", err)
	}
	slog.Info("phase 1: malicious candidates", slog.Int("count", len(candidates)))
	result.RequestsProcessed += len(candidates)

	// Enrich all candidates.
	enriched := make([]EnrichedRequest, 0, len(candidates))
	for _, rwd := range candidates {
		req := rwd.Request
		er := EnrichedRequest{
			RequestID:    req.ID,
			SourceIP:     req.SourceIP,
			SessionID:    req.SessionID,
			TimeReceived: req.TimeReceived,
			Features:     NewFeatureSet(),
		}
		// Set base request features.
		er.Features.Set("source_ip", req.SourceIP)
		er.Features.Set("cmp_hash", req.CmpHash)
		er.Features.Set("base_hash", req.BaseHash)
		er.Features.Set("uri", req.Uri)
		er.Features.Set("method", req.Method)
		er.Features.Set("app_id", strconv.FormatInt(req.AppID, 10))

		if err := p.registry.EnrichAll(ctx, &er); err != nil {
			slog.Warn("enrichment failed", slog.Int64("request_id", req.ID), slog.String("error", err.Error()))
		}
		enriched = append(enriched, er)
	}

	// Match against active campaign fingerprints.
	var unmatched []EnrichedRequest
	for _, er := range enriched {
		matched := false
		var bestCampaignID int64
		var bestScore float64

		for _, c := range activeCampaigns {
			fp, ok := fingerprints[c.ID]
			if !ok {
				continue
			}
			score := ScoreAgainstFingerprint(er.Features, fp, p.weights)
			if score >= p.cfg.Agent.SimilarityThreshold && score > bestScore {
				bestScore = score
				bestCampaignID = c.ID
				matched = true
			}
		}

		if matched {
			if err := p.addSeed(bestCampaignID, er, fingerprints, result); err != nil {
				slog.Warn("failed to add seed", slog.Int64("campaign_id", bestCampaignID), slog.String("error", err.Error()))
				result.Errors = append(result.Errors, err)
			}
			modifiedIDs[bestCampaignID] = true
		} else {
			unmatched = append(unmatched, er)
		}
	}

	slog.Info("phase 1: matched to existing", slog.Int("matched", len(enriched)-len(unmatched)), slog.Int("unmatched", len(unmatched)))

	// Cluster unmatched requests.
	clusters := ClusterUnmatched(unmatched, p.weights, p.cfg.Agent.SimilarityThreshold)

	slog.Info("phase 1: clusters", slog.Int("count", len(clusters)))

	// Create new campaigns from qualifying clusters.
	var newCampaigns []models.Campaign
	for _, cluster := range clusters {
		clusterRequests := make([]EnrichedRequest, len(cluster))
		for i, idx := range cluster {
			clusterRequests[i] = unmatched[idx]
		}

		if !p.qualifiesAsCampaign(clusterRequests) {
			continue
		}

		campaign, err := p.createCampaign(ctx, clusterRequests, fingerprints, result)
		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		}
		if campaign != nil {
			newCampaigns = append(newCampaigns, *campaign)
		}
	}

	return newCampaigns, modifiedIDs, nil
}

// fetchMaliciousCandidates queries unassigned malicious requests in the window
// by joining with request_description to check AI maliciousness classification.
func (p *Pipeline) fetchMaliciousCandidates(windowStart, windowEnd time.Time) ([]models.RequestWithDescription, error) {
	return p.db.CampaignGetUnassignedRequestsWithDescriptions(true, windowStart, windowEnd)
}

// addSeed adds a request as a seed to a campaign.
func (p *Pipeline) addSeed(campaignID int64, er EnrichedRequest, fingerprints map[int64]Fingerprint, result *PipelineResult) error {
	if p.dryRun {
		result.SeedsAdded++
		return nil
	}

	// Insert campaign_request link.
	link := models.CampaignRequest{
		CampaignID: campaignID,
		RequestID:  er.RequestID,
		Role:       constants.CampaignRequestRoleSeed,
	}
	if _, err := p.db.Insert(&link); err != nil {
		return fmt.Errorf("inserting campaign_request link: %w", err)
	}

	// Update request's denormalized campaign_id.
	req, err := p.db.GetRequestByID(er.RequestID)
	if err == nil {
		req.CampaignID = &campaignID
		if err := p.db.Update(&req); err != nil {
			slog.Warn("failed to update request campaign_id", slog.Int64("request_id", er.RequestID), slog.String("error", err.Error()))
		}
	}

	// Expand fingerprint.
	if fp, ok := fingerprints[campaignID]; ok {
		fp.Expand(er.Features)
	}

	result.SeedsAdded++
	return nil
}

// qualifiesAsCampaign checks if a cluster meets the campaign creation threshold.
func (p *Pipeline) qualifiesAsCampaign(requests []EnrichedRequest) bool {
	if len(requests) >= p.cfg.Agent.CampaignMinRequests {
		return true
	}
	uniqueIPs := make(map[string]bool)
	for _, r := range requests {
		if r.SourceIP != "" {
			uniqueIPs[r.SourceIP] = true
		}
	}
	return len(uniqueIPs) >= p.cfg.Agent.CampaignMinSourceIPs
}

// createCampaign creates a new campaign from a cluster of enriched requests.
func (p *Pipeline) createCampaign(ctx context.Context, requests []EnrichedRequest, fingerprints map[int64]Fingerprint, result *PipelineResult) (*models.Campaign, error) {
	// Build fingerprint from cluster.
	featureSets := make([]FeatureSet, len(requests))
	for i, r := range requests {
		featureSets[i] = r.Features
	}
	fp := CreateFromFeatureSets(featureSets)
	fpJSON, err := fp.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("serializing fingerprint: %w", err)
	}

	// Determine time range from actual request timestamps.
	firstSeen := requests[0].TimeReceived
	lastSeen := requests[0].TimeReceived
	for _, r := range requests[1:] {
		if r.TimeReceived.Before(firstSeen) {
			firstSeen = r.TimeReceived
		}
		if r.TimeReceived.After(lastSeen) {
			lastSeen = r.TimeReceived
		}
	}

	campaign := models.Campaign{
		Status:           constants.CampaignStatusActive,
		Severity:         constants.CampaignSeverityLow,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		Fingerprint:      fpJSON,
		AggregationState: json.RawMessage("{}"),
	}

	// Collect arrays for the campaign model.
	ipsSet := make(map[string]bool)
	for _, r := range requests {
		if r.SourceIP != "" {
			ipsSet[r.SourceIP] = true
		}
	}

	campaign.RequestCount = int64(len(requests))

	if p.dryRun {
		slog.Info("dry-run: would create campaign",
			slog.Int("request_count", len(requests)),
			slog.Int("unique_ips", len(ipsSet)),
		)
		result.CampaignsCreated++
		return nil, nil
	}

	// Insert campaign.
	inserted, err := p.db.Insert(&campaign)
	if err != nil {
		return nil, fmt.Errorf("inserting campaign: %w", err)
	}
	newCampaign := inserted.(*models.Campaign)
	fingerprints[newCampaign.ID] = fp

	// Link all requests via campaign_request rows.
	requestIDs := make([]int64, 0, len(requests))
	for _, r := range requests {
		link := models.CampaignRequest{
			CampaignID: newCampaign.ID,
			RequestID:  r.RequestID,
			Role:       constants.CampaignRequestRoleSeed,
		}
		if _, err := p.db.Insert(&link); err != nil {
			slog.Warn("failed to link request to new campaign",
				slog.Int64("campaign_id", newCampaign.ID),
				slog.Int64("request_id", r.RequestID),
				slog.String("error", err.Error()),
			)
		}
		requestIDs = append(requestIDs, r.RequestID)
	}

	// Bulk-update denormalized campaign_id on all requests in one round-trip.
	if err := p.db.ExecStatement(
		"UPDATE request SET campaign_id = $1 WHERE id = ANY($2)",
		newCampaign.ID, requestIDs,
	); err != nil {
		slog.Warn("failed to bulk-update request campaign_id",
			slog.Int64("campaign_id", newCampaign.ID),
			slog.String("error", err.Error()),
		)
	}

	result.CampaignsCreated++
	slog.Info("created new campaign",
		slog.Int64("campaign_id", newCampaign.ID),
		slog.Int("request_count", len(requests)),
	)

	return newCampaign, nil
}

// retroactiveLookback searches for historical matching requests for new campaigns.
func (p *Pipeline) retroactiveLookback(ctx context.Context, windowStart time.Time, newCampaigns []models.Campaign, fingerprints map[int64]Fingerprint, result *PipelineResult) {
	lookbackStart := windowStart.Add(-p.cfg.Agent.RetroactiveLookback)

	for _, c := range newCampaigns {
		fp, ok := fingerprints[c.ID]
		if !ok {
			continue
		}

		historicalRwds, err := p.db.CampaignGetUnassignedRequestsWithDescriptions(true, lookbackStart, windowStart)
		if err != nil {
			slog.Warn("retroactive lookback query failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			continue
		}

		for _, rwd := range historicalRwds {
			req := rwd.Request
			er := EnrichedRequest{
				RequestID:    req.ID,
				SourceIP:     req.SourceIP,
				SessionID:    req.SessionID,
				TimeReceived: req.TimeReceived,
				Features:     NewFeatureSet(),
			}
			er.Features.Set("source_ip", req.SourceIP)
			er.Features.Set("cmp_hash", req.CmpHash)
			er.Features.Set("base_hash", req.BaseHash)
			er.Features.Set("uri", req.Uri)
			er.Features.Set("method", req.Method)
			er.Features.Set("app_id", strconv.FormatInt(req.AppID, 10))

			_ = p.registry.EnrichAll(ctx, &er)

			score := ScoreAgainstFingerprint(er.Features, fp, p.weights)
			if score >= p.cfg.Agent.SimilarityThreshold {
				if err := p.addSeed(c.ID, er, fingerprints, result); err != nil {
					slog.Warn("retroactive seed failed", slog.String("error", err.Error()))
				}
				// Update first_seen_at if this is earlier.
				if req.TimeReceived.Before(c.FirstSeenAt) {
					c.FirstSeenAt = req.TimeReceived
					if !p.dryRun {
						_ = p.db.Update(&c)
					}
				}
			}
		}
	}
}

// phase2Correlate implements Phase 2: correlation of non-malicious requests.
func (p *Pipeline) phase2Correlate(ctx context.Context, campaigns []models.Campaign, result *PipelineResult) {
	if len(p.correlators) == 0 {
		return
	}

	slog.Debug("phase2Correlate: starting correlation phase")
	for _, c := range campaigns {
		if c.Status != constants.CampaignStatusActive {
			continue
		}

		// Build seed data for correlation.
		seedData, err := p.buildSeedData(c.ID)
		if err != nil {
			slog.Warn("failed to build seed data", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			continue
		}

		// Query non-malicious requests in the campaign's padded time window.
		paddedStart := c.FirstSeenAt.Add(-p.cfg.Agent.CorrelationPadding)
		paddedEnd := c.LastSeenAt.Add(p.cfg.Agent.CorrelationPadding)

		candidateRwds, err := p.db.CampaignGetUnassignedRequestsWithDescriptions(false, paddedStart, paddedEnd)
		if err != nil {
			slog.Warn("correlation query failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			continue
		}

		for _, rwd := range candidateRwds {
			req := rwd.Request
			candidate := CandidateRequest{
				RequestID: req.ID,
				SourceIP:  req.SourceIP,
				SessionID: req.SessionID,
			}

			if MatchAny(p.correlators, candidate, seedData) {
				if p.dryRun {
					result.CorrelatedAdded++
					continue
				}
				link := models.CampaignRequest{
					CampaignID: c.ID,
					RequestID:  req.ID,
					Role:       constants.CampaignRequestRoleCorrelated,
				}
				if _, err := p.db.Insert(&link); err != nil {
					continue // Duplicate is expected (unique index).
				}
				req.CampaignID = &c.ID
				_ = p.db.Update(&req)
				result.CorrelatedAdded++
			}
		}
	}
}

// buildSeedData collects session IDs, source IPs, and subnets from a campaign's seeds.
func (p *Pipeline) buildSeedData(campaignID int64) (CampaignSeedData, error) {
	data := NewCampaignSeedData()

	links, err := p.db.SearchCampaignRequests(0, MaxCampaignRequestLinks, fmt.Sprintf("campaign_id:%d role:seed", campaignID))
	if err != nil {
		return data, err
	}

	for _, link := range links {
		req, err := p.db.GetRequestByID(link.RequestID)
		if err != nil {
			continue
		}
		if req.SourceIP != "" {
			data.SourceIPs[req.SourceIP] = true
		}
		if req.SessionID != 0 {
			data.SessionIDs[req.SessionID] = true
		}
		// Subnet from whois, if available.
		whoisResults, err := p.db.SearchWhois(0, 1, fmt.Sprintf("ip:%s", req.SourceIP))
		if err == nil && len(whoisResults) > 0 && len(whoisResults[0].Rdap) > 0 {
			parser := whoisPkg.NewRdapParser(string(whoisResults[0].Rdap))
			if network, err := parser.GetNetwork(); err == nil {
				data.AddSubnet(network.String())
			}
		}
	}

	return data, nil
}

// phase3Merge implements Phase 3: campaign merging.
func (p *Pipeline) phase3Merge(ctx context.Context, campaigns []models.Campaign, fingerprints map[int64]Fingerprint, modifiedIDs map[int64]bool, result *PipelineResult) {
	if len(campaigns) < 2 {
		return
	}

	slog.Debug("phase3Merge: starting merge phase")

	// Build campaign index for quick lookup.
	campaignByID := make(map[int64]*models.Campaign)
	for i := range campaigns {
		campaignByID[campaigns[i].ID] = &campaigns[i]
	}

	// Only compare modified campaigns against all active ones.
	var pairs []mergePair

	for modID := range modifiedIDs {
		modFP, ok := fingerprints[modID]
		if !ok {
			continue
		}
		for _, c := range campaigns {
			if c.ID == modID || c.Status == constants.CampaignStatusMerged {
				continue
			}
			otherFP, ok := fingerprints[c.ID]
			if !ok {
				continue
			}

			// Score fingerprint similarity by checking overlap.
			score := p.scoreFingerprintPair(modFP, otherFP)
			if score >= p.cfg.Agent.SimilarityThreshold {
				// Older campaign (by ID) survives.
				survivorID, absorbedID := modID, c.ID
				if c.ID < modID {
					survivorID, absorbedID = c.ID, modID
				}
				pairs = append(pairs, mergePair{survivorID, absorbedID})
			}
		}
	}

	// Resolve transitive chains: if A→B and B→C, all merge into the smallest ID.
	resolved := p.resolveTransitiveMerges(pairs)

	// Execute merges.
	for absorbedID, survivorID := range resolved {
		if p.dryRun {
			slog.Info("dry-run: would merge campaigns", slog.Int64("absorbed", absorbedID), slog.Int64("survivor", survivorID))
			result.CampaignsMerged++
			continue
		}

		if err := p.executeMerge(survivorID, absorbedID, fingerprints); err != nil {
			slog.Warn("merge failed", slog.Int64("absorbed", absorbedID), slog.Int64("survivor", survivorID), slog.String("error", err.Error()))
			result.Errors = append(result.Errors, err)
			continue
		}
		result.CampaignsMerged++

		// Update in-memory state.
		if absorbed, ok := campaignByID[absorbedID]; ok {
			absorbed.Status = constants.CampaignStatusMerged
		}
	}
}

// scoreFingerprintPair scores the similarity between two fingerprints by
// checking how many feature values overlap, weighted by the feature weights.
func (p *Pipeline) scoreFingerprintPair(a, b Fingerprint) float64 {
	var score float64
	for feature, weight := range p.weights {
		if weight == 0 {
			continue
		}
		aVals, aOk := a[feature]
		bVals, bOk := b[feature]
		if !aOk || !bOk {
			continue
		}
		// Check if any value overlaps.
		for v := range aVals {
			if bVals[v] {
				score += weight
				break // One overlap per feature is enough.
			}
		}
	}
	return score
}

// resolveTransitiveMerges resolves transitive merge chains.
// Input: pairs of (survivor, absorbed). Output: map of absorbed -> final survivor.
func (p *Pipeline) resolveTransitiveMerges(pairs []mergePair) map[int64]int64 {
	if len(pairs) == 0 {
		return nil
	}

	// Build a union-find to resolve chains.
	parent := make(map[int64]int64)
	var find func(int64) int64
	find = func(x int64) int64 {
		if p, ok := parent[x]; ok && p != x {
			parent[x] = find(p)
			return parent[x]
		}
		if _, ok := parent[x]; !ok {
			parent[x] = x
		}
		return x
	}

	union := func(a, b int64) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// Smaller ID (older campaign) is the root.
		if ra > rb {
			ra, rb = rb, ra
		}
		parent[rb] = ra
	}

	for _, pair := range pairs {
		union(pair.survivorID, pair.absorbedID)
	}

	// Build result: every non-root maps to its root.
	result := make(map[int64]int64)
	for _, pair := range pairs {
		root := find(pair.absorbedID)
		if root != pair.absorbedID {
			result[pair.absorbedID] = root
		}
		// Also check survivorID in case it gets absorbed transitively.
		rootSurvivor := find(pair.survivorID)
		if rootSurvivor != pair.survivorID {
			result[pair.survivorID] = rootSurvivor
		}
	}

	return result
}

// executeMerge moves links from the absorbed campaign to the survivor.
func (p *Pipeline) executeMerge(survivorID, absorbedID int64, fingerprints map[int64]Fingerprint) error {
	// Move campaign_request links.
	links, err := p.db.SearchCampaignRequests(0, MaxCampaignRequestLinks, fmt.Sprintf("campaign_id:%d", absorbedID))
	if err != nil {
		return fmt.Errorf("fetching links for absorbed campaign: %w", err)
	}

	for _, link := range links {
		// Try to insert a new link for the survivor. The unique index
		// (campaign_id, request_id) will prevent duplicates.
		newLink := models.CampaignRequest{
			CampaignID: survivorID,
			RequestID:  link.RequestID,
			Role:       link.Role,
		}
		if _, err := p.db.Insert(&newLink); err != nil {
			// Duplicate — expected, skip.
			continue
		}
		// Update denormalized campaign_id on the request.
		req, err := p.db.GetRequestByID(link.RequestID)
		if err == nil {
			req.CampaignID = &survivorID
			_ = p.db.Update(&req)
		}
	}

	// Delete old links from absorbed campaign.
	for _, link := range links {
		_ = p.db.Delete(&link)
	}

	// Union fingerprints.
	survivorFP, sOk := fingerprints[survivorID]
	absorbedFP, aOk := fingerprints[absorbedID]
	if sOk && aOk {
		survivorFP.Union(absorbedFP)
	}

	// Update survivor time range.
	survivor, err := p.db.GetCampaignByID(survivorID)
	if err != nil {
		return fmt.Errorf("fetching survivor campaign: %w", err)
	}
	absorbed, err := p.db.GetCampaignByID(absorbedID)
	if err != nil {
		return fmt.Errorf("fetching absorbed campaign: %w", err)
	}

	if absorbed.FirstSeenAt.Before(survivor.FirstSeenAt) {
		survivor.FirstSeenAt = absorbed.FirstSeenAt
	}
	if absorbed.LastSeenAt.After(survivor.LastSeenAt) {
		survivor.LastSeenAt = absorbed.LastSeenAt
	}
	if sOk {
		fpJSON, err := survivorFP.ToJSON()
		if err == nil {
			survivor.Fingerprint = fpJSON
		}
	}
	survivor.RequestCount += absorbed.RequestCount

	if err := p.db.Update(&survivor); err != nil {
		return fmt.Errorf("updating survivor campaign: %w", err)
	}

	// Mark absorbed as MERGED.
	absorbed.Status = constants.CampaignStatusMerged
	absorbed.MergedIntoID = &survivorID
	if err := p.db.Update(&absorbed); err != nil {
		return fmt.Errorf("updating absorbed campaign: %w", err)
	}

	slog.Info("merged campaigns", slog.Int64("absorbed", absorbedID), slog.Int64("survivor", survivorID))
	return nil
}

// phase4Summarize computes aggregation state and optionally runs LLM summarization.
func (p *Pipeline) phase4Summarize(ctx context.Context, campaigns []models.Campaign, result *PipelineResult) {
	for i := range campaigns {
		c := &campaigns[i]
		if c.Status == constants.CampaignStatusMerged {
			continue
		}

		// Compute aggregation state.
		aggState, err := ComputeAggregationState(p.db, c.ID)
		if err != nil {
			slog.Warn("aggregation failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			result.Errors = append(result.Errors, err)
			continue
		}

		aggJSON, err := aggState.ToJSON()
		if err != nil {
			slog.Warn("aggregation JSON failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			continue
		}

		if p.dryRun {
			slog.Info("dry-run: aggregation state computed", slog.Int64("campaign_id", c.ID))
			continue
		}

		c.AggregationState = aggJSON

		// LLM summarization.
		if !p.skipLLM && p.summarizer != nil {
			needsResummarize := p.needsResummarization(c, aggState)
			if needsResummarize {
				name, summary, severity, err := p.summarizer.Summarize(ctx, aggJSON)
				if err != nil {
					slog.Warn("LLM summarization failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
					result.Errors = append(result.Errors, err)
				} else {
					if name != "" {
						c.Name = name
					}
					if summary != "" {
						c.Summary = summary
					}
					c.Severity = ValidateCampaignSeverity(severity)
					result.LLMCalls++
				}
			}
		}

		c.RequestCount = int64(aggState.Behavior.TotalRequests)
		c.SourceCountries = aggState.Sources.UniqueCountries
		c.TargetedApps = aggState.AttackProfile.TargetedApps
		c.TargetedCVEs = aggState.AttackProfile.CVEs

		// Update time range from aggregation (actual request timestamps).
		if aggState.Timeline.FirstSeen != "" {
			if t, err := time.Parse(time.RFC3339, aggState.Timeline.FirstSeen); err == nil {
				c.FirstSeenAt = t
			}
		}
		if aggState.Timeline.LastSeen != "" {
			if t, err := time.Parse(time.RFC3339, aggState.Timeline.LastSeen); err == nil {
				c.LastSeenAt = t
			}
		}

		if err := p.db.Update(c); err != nil {
			slog.Warn("campaign update failed", slog.Int64("campaign_id", c.ID), slog.String("error", err.Error()))
			result.Errors = append(result.Errors, err)
		} else {
			result.CampaignsUpdated++
		}
	}
}

// needsResummarization checks if the aggregation state changed significantly.
func (p *Pipeline) needsResummarization(c *models.Campaign, newState *AggregationState) bool {
	// Always summarize new campaigns (no name yet).
	if c.Name == "" {
		return true
	}
	if c.RequestCount == 0 {
		return false
	}

	// Check if request count grew by more than the threshold.
	growth := float64(newState.Behavior.TotalRequests-int(c.RequestCount)) / float64(c.RequestCount)
	return growth >= p.cfg.Agent.ResummarizeThreshold
}

// phase4Lifecycle implements lifecycle transitions.
func (p *Pipeline) phase4Lifecycle(ctx context.Context, campaigns []models.Campaign, now time.Time, result *PipelineResult) {
	for i := range campaigns {
		c := &campaigns[i]
		if c.Status == constants.CampaignStatusMerged {
			continue
		}

		timeSinceLastSeen := now.Sub(c.LastSeenAt)

		switch c.Status {
		case constants.CampaignStatusActive:
			if timeSinceLastSeen > p.cfg.Agent.ActiveWindow {
				c.Status = constants.CampaignStatusDormant
				if !p.dryRun {
					_ = p.db.Update(c)
				}
				result.CampaignsDormant++
				slog.Info("campaign transitioned to DORMANT", slog.Int64("campaign_id", c.ID))
			}
		case constants.CampaignStatusDormant:
			if timeSinceLastSeen > p.cfg.Agent.CloseWindow {
				c.Status = constants.CampaignStatusClosed
				// Generate final summary on close.
				if !p.skipLLM && p.summarizer != nil && !p.dryRun {
					aggState, err := ComputeAggregationState(p.db, c.ID)
					if err == nil {
						aggJSON, err := aggState.ToJSON()
						if err == nil {
							name, summary, severity, err := p.summarizer.Summarize(ctx, aggJSON)
							if err == nil {
								if name != "" {
									c.Name = name
								}
								if summary != "" {
									c.Summary = summary
								}
								c.Severity = ValidateCampaignSeverity(severity)
								result.LLMCalls++
							}
						}
					}
				}
				if !p.dryRun {
					_ = p.db.Update(c)
				}
				result.CampaignsClosed++
				slog.Info("campaign transitioned to CLOSED", slog.Int64("campaign_id", c.ID))
			}
		}
	}
}
