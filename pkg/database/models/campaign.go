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
package models

import (
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type Campaign struct {
	ID               int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the campaign"`
	Name             string                   `ksql:"name" json:"name" doc:"LLM-generated campaign name"`
	Summary          string                   `ksql:"summary" json:"summary" doc:"LLM-generated narrative summary"`
	Severity         string                   `ksql:"severity" json:"severity" doc:"Assessed severity (e.g. LOW, MEDIUM, HIGH, CRITICAL)"`
	Status           string                   `ksql:"status" json:"status" doc:"Campaign status: ACTIVE, DORMANT, CLOSED, MERGED"`
	MergedIntoID     *int64                   `ksql:"merged_into_id" json:"merged_into_id" doc:"ID of the campaign this was merged into (nil if not merged)"`
	FirstSeenAt      time.Time                `ksql:"first_seen_at" json:"first_seen_at" doc:"Timestamp of the earliest request in the campaign"`
	LastSeenAt       time.Time                `ksql:"last_seen_at" json:"last_seen_at" doc:"Timestamp of the most recent request in the campaign"`
	SourceASNs       pgtype.FlatArray[string] `ksql:"source_asns" json:"source_asns" doc:"Source ASNs observed in this campaign"`
	SourceCountries  pgtype.FlatArray[string] `ksql:"source_countries" json:"source_countries" doc:"Source countries observed in this campaign"`
	TargetedApps     pgtype.FlatArray[string] `ksql:"targeted_apps" json:"targeted_apps" doc:"Targeted applications in this campaign"`
	TargetedCVEs     pgtype.FlatArray[string] `ksql:"targeted_cves" json:"targeted_cves" doc:"Targeted CVEs in this campaign"`
	RequestCount     int64                    `ksql:"request_count" json:"request_count" doc:"Total number of requests in this campaign"`
	Fingerprint      string                   `ksql:"fingerprint" json:"fingerprint" doc:"JSON-encoded feature values defining this campaign"`
	AggregationState json.RawMessage          `ksql:"aggregation_state" json:"aggregation_state" doc:"JSON-encoded aggregated campaign data, sole input for LLM summarization"`
	EnabledSources   pgtype.FlatArray[string] `ksql:"enabled_sources" json:"enabled_sources" doc:"Sources that contributed to this campaign"`
	CreatedAt        time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"When the campaign was created"`
	UpdatedAt        time.Time                `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"When the campaign was last updated"`
}

func (c *Campaign) ModelID() int64 { return c.ID }
