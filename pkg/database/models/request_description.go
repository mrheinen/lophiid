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
package models

import "time"

type RequestDescription struct {
	ID                  int64     `ksql:"id,skipInserts" json:"id"`
	ExampleRequestID    int64     `ksql:"example_request_id" json:"example_request_id" doc:"The ID of a request related to the event"`
	CreatedAt           time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"When the hash was created in the database"`
	UpdatedAt           time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Last time this record was updated"`
	CmpHash             string    `ksql:"cmp_hash" json:"cmp_hash" doc:"The cmp hash of the request"`
	AIDescription       string    `ksql:"ai_description" json:"ai_description" doc:"An AI generated description of the request"`
	AIMalicious         string    `ksql:"ai_malicious" json:"ai_malicious" doc:"An AI generated maliciousness rating"`
	AIApplication       string    `ksql:"ai_application" json:"ai_application" doc:"An AI generated application name"`
	AIVulnerabilityType string    `ksql:"ai_vulnerability_type" json:"ai_vulnerability_type" doc:"An AI generated vulnerability type that is exploited"`
	AIHasPayload        string    `ksql:"ai_has_payload" json:"ai_has_payload" doc:"Whether the AI thinks a malicious payload is present"`
	AICVE               string    `ksql:"ai_cve" json:"ai_cve" doc:"The CVE the AI thinks is related - highly incorrect"`
	ReviewStatus        string    `ksql:"review_status" json:"review_status" doc:"Whether the AI data was manually reviewed (excluding CVE)"`
	SourceModel         string    `ksql:"source_model" json:"source_model" doc:"The model used to generate the AI data"`
	TriageStatus        string    `ksql:"triage_status" json:"triage_status" doc:"Whether the request was triaged"`
}

func (c *RequestDescription) ModelID() int64 { return c.ID }
