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
	"sort"
	"time"

	"lophiid/pkg/database"
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
	MaxTags                 = 50
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
	Tags           []string             `json:"tags"`
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
// linked requests and enrichment data. This is a pure DB aggregation.
func ComputeAggregationState(db database.DatabaseClient, campaignID int64) (*AggregationState, error) {
	// Fetch all campaign_request links.
	links, err := db.SearchCampaignRequests(0, MaxCampaignRequestLinks, fmt.Sprintf("campaign_id:%d", campaignID))
	if err != nil {
		return nil, fmt.Errorf("fetching campaign_request links: %w", err)
	}
	if len(links) == 0 {
		return &AggregationState{}, nil
	}

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
	tagSet := make(map[string]bool)
	osMap := make(map[string]int)

	var firstSeen, lastSeen time.Time
	seedCount := 0
	correlatedCount := 0

	for _, link := range links {
		req, err := db.GetRequestByID(link.RequestID)
		if err != nil {
			continue // Skip missing requests.
		}

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
		if link.Role == constants.CampaignRequestRoleSeed {
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

		// Request description enrichment (AI triage).
		if req.CmpHash != "" {
			descs, err := db.SearchRequestDescription(0, 1, fmt.Sprintf("cmp_hash:%s", req.CmpHash))
			if err == nil && len(descs) > 0 {
				d := descs[0]
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

		// Tags.
		tags, err := db.GetTagPerRequestFullForRequest(req.ID)
		if err == nil {
			for _, t := range tags {
				tagSet[t.Tag.Name] = true
			}
		}

		// P0f.
		if req.SourceIP != "" {
			p0f, err := db.GetP0fResultByIP(req.SourceIP, "")
			if err == nil && p0f.OsName != "" {
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
	state.Sources.UniqueIPs = cappedStringSet(ips, MaxUniqueIPs)

	// Look up whois data per unique IP for countries and ASNs.
	countries := make(map[string]bool)
	for ip := range ips {
		whoisResults, err := db.SearchWhois(0, 1, fmt.Sprintf("ip:%s", ip))
		if err == nil && len(whoisResults) > 0 {
			w := whoisResults[0]
			if w.Country != "" {
				countries[w.Country] = true
			}
		}
	}
	state.Sources.UniqueCountries = cappedStringSet(countries, MaxCountries)

	// Populate attack profile.
	state.AttackProfile.TargetedApps = cappedStringSet(apps, MaxTargetedApps)
	state.AttackProfile.VulnerabilityTypes = cappedStringSet(vulnTypes, MaxVulnTypes)
	state.AttackProfile.MITRETechniques = cappedStringSet(mitre, MaxMITRETechniques)
	state.AttackProfile.CVEs = cappedStringSet(cves, MaxCVEs)
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
	for i, e := range uriList {
		if i >= MaxTopURIs {
			break
		}
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
	for os, count := range osMap {
		if len(state.OSFingerprints) >= MaxOSFingerprints {
			break
		}
		state.OSFingerprints = append(state.OSFingerprints, OSFingerprint{OS: os, Count: count})
	}

	// Tags.
	state.Tags = cappedStringSet(tagSet, MaxTags)

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

// cappedStringSet converts a set to a slice, capped at maxLen.
func cappedStringSet(set map[string]bool, maxLen int) []string {
	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	if len(result) > maxLen {
		result = result[:maxLen]
	}
	return result
}
