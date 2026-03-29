// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
)

// Capped array limits for aggregation state fields.
const (
	MaxUniqueIPs            = 50
	MaxUniqueASNs           = 20
	MaxCountries            = 20
	MaxNetworkRanges        = 30
	MaxTopURIs              = 20
	MaxSamplePayloads       = 10
	MaxScannerResults       = 20
	MaxOSFingerprints       = 10
	MaxTargetedApps         = 20
	MaxVulnTypes            = 20
	MaxMITRETechniques      = 20
	MaxCVEs                 = 20
	MaxCampaignRequestLinks = 100000
	MaxDownloads            = 1000
)

// AggregationState is the structured data computed from a campaign's linked
// requests. It is the sole input for LLM summarization.
type AggregationState struct {
	Timeline       TimelineSection      `json:"timeline"`
	Sources        SourcesSection       `json:"sources"`
	AttackProfile  AttackProfileSection `json:"attack_profile"`
	Behavior       BehaviorSection      `json:"behavior"`
	VTScanResults  []VTScanResult       `json:"vt_scanner_results"`
	OSFingerprints []OSFingerprint      `json:"os_fingerprints"`
}

// TimelineSection holds temporal data about the campaign.
type TimelineSection struct {
	FirstSeen         string         `json:"first_seen"`
	LastSeen          string         `json:"last_seen"`
	ActiveDays        int            `json:"active_days"`
	ActivityHistogram map[string]int `json:"activity_histogram"`
}

// SourcesSection holds network origin data.
type SourcesSection struct {
	UniqueIPs           []string `json:"unique_ips"`
	UniqueASNs          []string `json:"unique_asns"`
	UniqueCountries     []string `json:"unique_countries"`
	UniqueNetworkRanges []string `json:"unique_network_ranges"`
}

// AttackProfileSection holds attack characteristics.
type AttackProfileSection struct {
	TargetedApps        []string   `json:"targeted_apps"`
	VulnerabilityTypes  []string   `json:"vulnerability_types"`
	MITRETechniques     []string   `json:"mitre_techniques"`
	CVEs                []string   `json:"cves"`
	TopURIs             []URICount `json:"top_uris"`
	UniquePayloadHashes int        `json:"unique_payload_hashes"`
	SamplePayloads      []string   `json:"sample_payloads"`
}

// URICount pairs a URI with its request count.
type URICount struct {
	URI   string `json:"uri"`
	Count int    `json:"count"`
}

// BehaviorSection holds behavioral statistics.
type BehaviorSection struct {
	TotalRequests        int            `json:"total_requests"`
	MaliciousSeedCount   int            `json:"malicious_seed_count"`
	CorrelatedReconCount int            `json:"correlated_recon_count"`
	HTTPMethods          map[string]int `json:"http_methods"`
	HasDownloads         bool           `json:"has_downloads"`
	DownloadCount        int            `json:"download_count"`
	DownloadVerdicts     []string       `json:"download_verdicts"`
}

// VTScanResult holds VirusTotal analysis for a single download.
type VTScanResult struct {
	SHA256            string   `json:"sha256"`
	VTMalicious       int64    `json:"vt_malicious"`
	VTSuspicious      int64    `json:"vt_suspicious"`
	VTHarmless        int64    `json:"vt_harmless"`
	ScannerDetections []string `json:"scanner_detections"`
}

// OSFingerprint holds a p0f OS fingerprint with count.
type OSFingerprint struct {
	OS    string `json:"os"`
	Count int    `json:"count"`
}

// ComputeAggregationState builds the aggregation state for a campaign from its
// linked requests and enrichment data. Uses bulk queries to avoid N+1 DB
// round-trips.
func ComputeAggregationState(db database.DatabaseClient, campaignID int64) (*AggregationState, error) {
	slog.Debug("computing aggregation state for campaign", slog.Int64("campaign_id", campaignID))
	// Fetch all campaign_request links.
	links, err := db.SearchCampaignRequests(0, MaxCampaignRequestLinks, fmt.Sprintf("campaign_id:%d", campaignID))
	if err != nil {
		return nil, fmt.Errorf("fetching campaign_request links: %w", err)
	}
	if len(links) == 0 {
		return &AggregationState{}, nil
	}

	// Build role lookup and collect request IDs for bulk fetch.
	roleByRequestID := make(map[int64]string, len(links))
	requestIDs := make([]int64, 0, len(links))
	for _, link := range links {
		roleByRequestID[link.RequestID] = link.Role
		requestIDs = append(requestIDs, link.RequestID)
	}

	// Bulk-fetch all requests in one query.
	var requests []models.Request
	if err := db.BulkGetByField("request", "id", requestIDs, &requests); err != nil {
		return nil, fmt.Errorf("bulk-fetching requests: %w", err)
	}

	// Collect unique cmp_hashes and source IPs for subsequent bulk fetches.
	cmpHashSet := make(map[string]bool)
	ipSet := make(map[string]bool)
	for _, req := range requests {
		if req.CmpHash != "" {
			cmpHashSet[req.CmpHash] = true
		}
		if req.SourceIP != "" {
			ipSet[req.SourceIP] = true
		}
	}

	uniqueHashes := make([]string, 0, len(cmpHashSet))
	for h := range cmpHashSet {
		uniqueHashes = append(uniqueHashes, h)
	}
	uniqueIPs := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		uniqueIPs = append(uniqueIPs, ip)
	}

	// Bulk-fetch request descriptions indexed by cmp_hash.
	descsByHash := make(map[string]models.RequestDescription)
	var descs []models.RequestDescription
	if err := db.BulkGetByField("request_description", "cmp_hash", uniqueHashes, &descs); err == nil {
		for _, d := range descs {
			descsByHash[d.CmpHash] = d
		}
	}

	// Bulk-fetch p0f results indexed by IP.
	p0fByIP := make(map[string]models.P0fResult)
	var p0fResults []models.P0fResult
	if err := db.BulkGetByField("p0f_result", "ip", uniqueIPs, &p0fResults); err == nil {
		for _, p := range p0fResults {
			p0fByIP[p.IP] = p
		}
	}

	// Bulk-fetch whois records indexed by IP.
	whoisByIP := make(map[string]models.Whois)
	var whoisResults []models.Whois
	if err := db.BulkGetByField("whois", "ip", uniqueIPs, &whoisResults); err == nil {
		for _, w := range whoisResults {
			whoisByIP[w.IP] = w
		}
	}

	// Iterate over fetched requests using in-memory maps — zero per-row queries.
	state := &AggregationState{
		Timeline: TimelineSection{
			ActivityHistogram: make(map[string]int),
		},
		Behavior: BehaviorSection{
			HTTPMethods: make(map[string]int),
		},
	}

	ips := make(map[string]bool)
	uriCounts := make(map[string]int)
	methods := make(map[string]int)
	payloadHashes := make(map[string]bool)
	samplePayloads := []string{}
	apps := make(map[string]bool)
	vulnTypes := make(map[string]bool)
	mitre := make(map[string]bool)
	cves := make(map[string]bool)
	osMap := make(map[string]int)

	var firstSeen, lastSeen time.Time
	seedCount := 0
	correlatedCount := 0

	for _, req := range requests {
		role := roleByRequestID[req.ID]

		// Timeline.
		if firstSeen.IsZero() || req.TimeReceived.Before(firstSeen) {
			firstSeen = req.TimeReceived
		}
		if lastSeen.IsZero() || req.TimeReceived.After(lastSeen) {
			lastSeen = req.TimeReceived
		}
		day := req.TimeReceived.Format("2006-01-02")
		state.Timeline.ActivityHistogram[day]++

		// Role counts.
		if role == constants.CampaignRequestRoleSeed {
			seedCount++
		} else {
			correlatedCount++
		}

		// Source IPs.
		if req.SourceIP != "" {
			ips[req.SourceIP] = true
		}

		// URI and method.
		uriCounts[req.Uri]++
		methods[req.Method]++

		// Payload hashes.
		if req.CmpHash != "" {
			payloadHashes[req.CmpHash] = true
		}
		if len(samplePayloads) < MaxSamplePayloads && len(req.Body) > 0 {
			payload := string(req.Body)
			if len(payload) > 200 {
				payload = payload[:200] + "..."
			}
			samplePayloads = append(samplePayloads, payload)
		}

		// Request description enrichment from pre-fetched map.
		if req.CmpHash != "" {
			if d, ok := descsByHash[req.CmpHash]; ok {
				if d.AIApplication != "" {
					apps[d.AIApplication] = true
				}
				if d.AIVulnerabilityType != "" {
					vulnTypes[d.AIVulnerabilityType] = true
				}
				if d.AIMitreAttack != "" {
					mitre[d.AIMitreAttack] = true
				}
				if d.AICVE != "" {
					cves[d.AICVE] = true
				}
			}
		}

		// P0f from pre-fetched map.
		if req.SourceIP != "" {
			if p0f, ok := p0fByIP[req.SourceIP]; ok && p0f.OsName != "" {
				osStr := p0f.OsName
				if p0f.OsVersion != "" {
					osStr += " " + p0f.OsVersion
				}
				osMap[osStr]++
			}
		}
	}

	state.Timeline.FirstSeen = firstSeen.Format(time.RFC3339)
	state.Timeline.LastSeen = lastSeen.Format(time.RFC3339)
	if !firstSeen.IsZero() && !lastSeen.IsZero() {
		state.Timeline.ActiveDays = int(lastSeen.Sub(firstSeen).Hours()/24) + 1
	}

	// Populate sources.
	state.Sources.UniqueIPs = mapKeys(ips)

	// Populate countries from pre-fetched whois map.
	countries := make(map[string]bool)
	for ip := range ips {
		if w, ok := whoisByIP[ip]; ok && w.Country != "" {
			countries[w.Country] = true
		}
	}
	state.Sources.UniqueCountries = mapKeys(countries)

	// Populate attack profile.
	state.AttackProfile.TargetedApps = mapKeys(apps)
	state.AttackProfile.VulnerabilityTypes = mapKeys(vulnTypes)
	state.AttackProfile.MITRETechniques = mapKeys(mitre)
	state.AttackProfile.CVEs = mapKeys(cves)
	state.AttackProfile.UniquePayloadHashes = len(payloadHashes)
	state.AttackProfile.SamplePayloads = samplePayloads

	// Top URIs by count.
	type uriEntry struct {
		uri   string
		count int
	}
	uriList := make([]uriEntry, 0, len(uriCounts))
	for u, c := range uriCounts {
		uriList = append(uriList, uriEntry{u, c})
	}
	sort.Slice(uriList, func(i, j int) bool { return uriList[i].count > uriList[j].count })
	for _, e := range uriList {
		state.AttackProfile.TopURIs = append(state.AttackProfile.TopURIs, URICount{URI: e.uri, Count: e.count})
	}

	// Populate behavior.
	state.Behavior.TotalRequests = len(links)
	state.Behavior.MaliciousSeedCount = seedCount
	state.Behavior.CorrelatedReconCount = correlatedCount
	state.Behavior.HTTPMethods = methods

	// Downloads and VT results scoped to the campaign's time window.
	dlQuery := fmt.Sprintf("created_at:>%s created_at:<%s",
		firstSeen.Format(time.RFC3339),
		lastSeen.Add(24*time.Hour).Format(time.RFC3339))
	downloads, err := db.SearchDownloads(0, MaxDownloads, dlQuery)
	if err == nil {
		// Filter to downloads whose request_id is in our campaign.
		linkRequestIDs := make(map[int64]bool)
		for _, l := range links {
			linkRequestIDs[l.RequestID] = true
		}
		for _, d := range downloads {
			if !linkRequestIDs[d.RequestID] {
				continue
			}
			state.Behavior.HasDownloads = true
			state.Behavior.DownloadCount++
			if d.VTAnalysisMalicious > 0 {
				state.Behavior.DownloadVerdicts = append(state.Behavior.DownloadVerdicts, "malicious")
			} else if d.VTAnalysisSuspicious > 0 {
				state.Behavior.DownloadVerdicts = append(state.Behavior.DownloadVerdicts, "suspicious")
			} else {
				state.Behavior.DownloadVerdicts = append(state.Behavior.DownloadVerdicts, "clean")
			}
			if len(state.VTScanResults) < MaxScannerResults {
				detections := []string{}
				for _, r := range d.VTFileAnalysisResult {
					detections = append(detections, r)
				}
				state.VTScanResults = append(state.VTScanResults, VTScanResult{
					SHA256:            d.SHA256sum,
					VTMalicious:       d.VTAnalysisMalicious,
					VTSuspicious:      d.VTAnalysisSuspicious,
					VTHarmless:        d.VTAnalysisHarmless,
					ScannerDetections: detections,
				})
			}
		}
	}

	// OS fingerprints.
	type osEntry struct {
		os    string
		count int
	}
	var osList []osEntry
	for os, count := range osMap {
		osList = append(osList, osEntry{os, count})
	}
	// Sort by count descending, then by OS name alphabetically for determinism.
	sort.Slice(osList, func(i, j int) bool {
		if osList[i].count == osList[j].count {
			return osList[i].os < osList[j].os
		}
		return osList[i].count > osList[j].count
	})
	for _, e := range osList {
		state.OSFingerprints = append(state.OSFingerprints, OSFingerprint{OS: e.os, Count: e.count})
	}

	return state, nil
}

// ToJSON serializes the aggregation state to JSON.
func (s *AggregationState) ToJSON() (json.RawMessage, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshaling aggregation state: %w", err)
	}
	return json.RawMessage(data), nil
}

// mapKeys converts a set to a slice.
func mapKeys(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	return result
}

// ToLLMPayload serializes a capped version of the aggregation state for LLM summarization.
func (s *AggregationState) ToLLMPayload() ([]byte, error) {
	capped := *s

	capped.Sources.UniqueIPs = capSlice(s.Sources.UniqueIPs, MaxUniqueIPs)
	capped.Sources.UniqueASNs = capSlice(s.Sources.UniqueASNs, MaxUniqueASNs)
	capped.Sources.UniqueCountries = capSlice(s.Sources.UniqueCountries, MaxCountries)
	capped.Sources.UniqueNetworkRanges = capSlice(s.Sources.UniqueNetworkRanges, MaxNetworkRanges)

	capped.AttackProfile.TargetedApps = capSlice(s.AttackProfile.TargetedApps, MaxTargetedApps)
	capped.AttackProfile.VulnerabilityTypes = capSlice(s.AttackProfile.VulnerabilityTypes, MaxVulnTypes)
	capped.AttackProfile.MITRETechniques = capSlice(s.AttackProfile.MITRETechniques, MaxMITRETechniques)
	capped.AttackProfile.CVEs = capSlice(s.AttackProfile.CVEs, MaxCVEs)
	capped.AttackProfile.SamplePayloads = capSlice(s.AttackProfile.SamplePayloads, MaxSamplePayloads)
	capped.AttackProfile.TopURIs = capSlice(s.AttackProfile.TopURIs, MaxTopURIs)

	capped.VTScanResults = capSlice(s.VTScanResults, MaxScannerResults)
	capped.OSFingerprints = capSlice(s.OSFingerprints, MaxOSFingerprints)

	return json.Marshal(capped)
}

func capSlice[T any](s []T, max int) []T {
	if len(s) > max {
		return s[:max]
	}
	return s
}
