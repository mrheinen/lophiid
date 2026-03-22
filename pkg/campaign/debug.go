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
	"fmt"
	"sort"
	"strconv"

	"lophiid/pkg/database"
)

// truncateValues truncates a string to maxLen characters, appending "..." if truncated.
func truncateValues(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// formatValueSet formats a map[string]bool as a compact string for display.
func formatValueSet(vals map[string]bool, maxLen int) string {
	if len(vals) == 0 {
		return "(empty)"
	}
	items := make([]string, 0, len(vals))
	for v := range vals {
		items = append(items, v)
	}
	sort.Strings(items)
	result := "{"
	for i, v := range items {
		if i > 0 {
			result += ", "
		}
		result += v
	}
	result += "}"
	if len(items) > 3 {
		result = fmt.Sprintf("{%s, %s, ... +%d more}", items[0], items[1], len(items)-2)
	}
	return truncateValues(result, maxLen)
}

// DebugMatchRequest loads a campaign fingerprint and a request, enriches the
// request using the source registry, then prints a feature-by-feature scoring
// breakdown showing why the request does or does not match the campaign.
func DebugMatchRequest(ctx context.Context, db database.DatabaseClient, registry *SourceRegistry, weights WeightMap, threshold float64, campaignID, requestID int64) error {
	// Load campaign.
	campaigns, err := db.SearchCampaigns(0, 1, fmt.Sprintf("id:%d", campaignID))
	if err != nil {
		return fmt.Errorf("loading campaign %d: %w", campaignID, err)
	}
	if len(campaigns) == 0 {
		return fmt.Errorf("campaign %d not found", campaignID)
	}
	c := campaigns[0]

	fp, err := FingerprintFromJSON(c.Fingerprint)
	if err != nil {
		return fmt.Errorf("parsing fingerprint for campaign %d: %w", campaignID, err)
	}

	// Load and enrich request.
	req, err := db.GetRequestByID(requestID)
	if err != nil {
		return fmt.Errorf("loading request %d: %w", requestID, err)
	}

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

	if err := registry.EnrichAll(ctx, &er); err != nil {
		fmt.Printf("WARNING: enrichment failed: %s\n", err)
	}

	// Print header.
	fmt.Printf("\n=== Debug Match: Request %d vs Campaign %d (%s) ===\n\n", requestID, campaignID, c.Name)
	fmt.Printf("Campaign status: %s | Requests: %d | First seen: %s | Last seen: %s\n",
		c.Status, c.RequestCount, c.FirstSeenAt.Format("2006-01-02"), c.LastSeenAt.Format("2006-01-02"))
	fmt.Printf("Request source IP: %s | URI: %s | Method: %s\n\n", req.SourceIP, req.Uri, req.Method)

	// Score feature by feature.
	features := sortedWeightKeys(weights)
	var totalScore float64

	fmt.Printf("%-28s | %6s | %-35s | %-25s | %s\n", "Feature", "Weight", "Fingerprint Values", "Request Value", "Result")
	fmt.Printf("%-28s-+-%6s-+-%35s-+-%25s-+-%s\n", "----------------------------", "------", "-----------------------------------", "-------------------------", "----------")

	for _, feature := range features {
		weight := weights[feature]
		fpVals := fp[feature]
		reqVal := er.Features.Get(feature)

		fpStr := formatValueSet(fpVals, 35)
		reqStr := truncateValues(reqVal, 25)
		if reqVal == "" {
			reqStr = "(empty)"
		}

		var resultStr string
		if reqVal == "" {
			resultStr = "- (no value)"
		} else if fp.Has(feature, reqVal) {
			totalScore += weight
			resultStr = fmt.Sprintf("MATCH +%.2f", weight)
		} else if len(fpVals) == 0 {
			resultStr = "- (no fp)"
		} else {
			resultStr = "NO MATCH"
		}

		fmt.Printf("%-28s | %6.2f | %-35s | %-25s | %s\n", feature, weight, fpStr, reqStr, resultStr)
	}

	// Also show request features not in weight map.
	for feature, val := range er.Features {
		if _, ok := weights[feature]; ok {
			continue
		}
		fmt.Printf("%-28s | %6s | %-35s | %-25s | %s\n", feature, "(n/a)", "(not weighted)", truncateValues(val, 25), "IGNORED")
	}

	fmt.Printf("\n%-28s   %6.2f / %.2f threshold", "TOTAL SCORE:", totalScore, threshold)
	if totalScore >= threshold {
		fmt.Printf(" → MATCH\n\n")
	} else {
		fmt.Printf(" → NO MATCH (need %.2f more)\n\n", threshold-totalScore)
	}

	return nil
}

// DebugMergeCampaigns loads two campaign fingerprints and prints a
// feature-by-feature scoring breakdown showing why they would or would not
// be merged.
func DebugMergeCampaigns(ctx context.Context, db database.DatabaseClient, weights WeightMap, threshold float64, campaignAID, campaignBID int64) error {
	// Load both campaigns.
	campaignsA, err := db.SearchCampaigns(0, 1, fmt.Sprintf("id:%d", campaignAID))
	if err != nil {
		return fmt.Errorf("loading campaign %d: %w", campaignAID, err)
	}
	if len(campaignsA) == 0 {
		return fmt.Errorf("campaign %d not found", campaignAID)
	}
	a := campaignsA[0]

	campaignsB, err := db.SearchCampaigns(0, 1, fmt.Sprintf("id:%d", campaignBID))
	if err != nil {
		return fmt.Errorf("loading campaign %d: %w", campaignBID, err)
	}
	if len(campaignsB) == 0 {
		return fmt.Errorf("campaign %d not found", campaignBID)
	}
	b := campaignsB[0]

	fpA, err := FingerprintFromJSON(a.Fingerprint)
	if err != nil {
		return fmt.Errorf("parsing fingerprint for campaign %d: %w", campaignAID, err)
	}
	fpB, err := FingerprintFromJSON(b.Fingerprint)
	if err != nil {
		return fmt.Errorf("parsing fingerprint for campaign %d: %w", campaignBID, err)
	}

	// Print header.
	fmt.Printf("\n=== Debug Merge: Campaign %d vs Campaign %d ===\n\n", campaignAID, campaignBID)
	fmt.Printf("Campaign A: id=%d name=%q status=%s requests=%d\n", a.ID, a.Name, a.Status, a.RequestCount)
	fmt.Printf("Campaign B: id=%d name=%q status=%s requests=%d\n\n", b.ID, b.Name, b.Status, b.RequestCount)

	// Score feature by feature (same logic as scoreFingerprintPair).
	features := sortedWeightKeys(weights)
	var totalScore float64

	fmt.Printf("%-28s | %6s | %-30s | %-30s | %s\n", "Feature", "Weight", "Campaign A Values", "Campaign B Values", "Result")
	fmt.Printf("%-28s-+-%6s-+-%30s-+-%30s-+-%s\n", "----------------------------", "------", "------------------------------", "------------------------------", "----------")

	for _, feature := range features {
		weight := weights[feature]
		aVals := fpA[feature]
		bVals := fpB[feature]

		aStr := formatValueSet(aVals, 30)
		bStr := formatValueSet(bVals, 30)

		var resultStr string
		if len(aVals) == 0 && len(bVals) == 0 {
			resultStr = "- (both empty)"
		} else if len(aVals) == 0 || len(bVals) == 0 {
			resultStr = "- (one empty)"
		} else {
			overlap := false
			for v := range aVals {
				if bVals[v] {
					overlap = true
					break
				}
			}
			if overlap {
				totalScore += weight
				resultStr = fmt.Sprintf("OVERLAP +%.2f", weight)
			} else {
				resultStr = "NO OVERLAP"
			}
		}

		fmt.Printf("%-28s | %6.2f | %-30s | %-30s | %s\n", feature, weight, aStr, bStr, resultStr)
	}

	// Show features present in fingerprints but not in weight map.
	allFpFeatures := make(map[string]bool)
	for k := range fpA {
		allFpFeatures[k] = true
	}
	for k := range fpB {
		allFpFeatures[k] = true
	}
	for feature := range allFpFeatures {
		if _, ok := weights[feature]; ok {
			continue
		}
		aStr := formatValueSet(fpA[feature], 30)
		bStr := formatValueSet(fpB[feature], 30)
		fmt.Printf("%-28s | %6s | %-30s | %-30s | %s\n", feature, "(n/a)", aStr, bStr, "IGNORED")
	}

	fmt.Printf("\n%-28s   %6.2f / %.2f threshold", "TOTAL SCORE:", totalScore, threshold)
	if totalScore >= threshold {
		fmt.Printf(" → WOULD MERGE\n\n")
	} else {
		fmt.Printf(" → NO MERGE (need %.2f more)\n\n", threshold-totalScore)
	}

	return nil
}

// sortedWeightKeys returns the weight map keys sorted alphabetically.
func sortedWeightKeys(weights WeightMap) []string {
	keys := make([]string, 0, len(weights))
	for k := range weights {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
