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
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CampaignExportDTO represents a newly-formed campaign cluster discovered
// during a dry run. EphemeralID is a local sequential identifier (not a DB ID)
// assigned at export time so that the tuning agent can correlate clusters with
// merge records.
type CampaignExportDTO struct {
	EphemeralID         int       `json:"ephemeral_id"`
	Name                string    `json:"name"`
	Severity            string    `json:"severity"`
	Status              string    `json:"status"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
	RequestCount        int       `json:"request_count"`
	ClusteredRequestIDs []int64   `json:"clustered_request_ids"`
	ClusteredIPs        []string  `json:"clustered_ips"`
}

// MergeExportDTO describes a pair of existing DB campaigns that would have
// been merged during a dry run. SurvivorCampaignID is the campaign that would
// survive; AbsorbedCampaignID is the one that would be consumed.
type MergeExportDTO struct {
	SurvivorCampaignID int64 `json:"survivor_campaign_id"`
	AbsorbedCampaignID int64 `json:"absorbed_campaign_id"`
}

// SeedAssignmentDTO describes a single request that was matched and would have
// been attached to an existing campaign during a dry run.
type SeedAssignmentDTO struct {
	CampaignID int64  `json:"campaign_id"`
	RequestID  int64  `json:"request_id"`
	SourceIP   string `json:"source_ip"`
}

// DryRunExportData is the top-level JSON structure written by --export-json.
// It captures every clustering decision the pipeline would have persisted had
// --dry-run not been active.
type DryRunExportData struct {
	// GeneratedAt is the UTC timestamp at which the export was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// NewClusters contains one entry per campaign cluster that would have been
	// created, with the full list of matched request IDs and source IPs.
	NewClusters []CampaignExportDTO `json:"new_clusters"`
	// Merges contains pairs of existing DB campaigns that would have been merged.
	Merges []MergeExportDTO `json:"merges"`
	// SeedAssignments lists requests that were matched to pre-existing campaigns.
	SeedAssignments []SeedAssignmentDTO `json:"seed_assignments"`
}

// ExportDryRunDataToFile serialises data as indented JSON and writes it to
// path, creating or truncating the file as needed.
func ExportDryRunDataToFile(data DryRunExportData, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating export file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encoding export data: %w", err)
	}
	return nil
}
