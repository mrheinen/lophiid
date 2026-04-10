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

import "time"

type SingleKillChainPhase struct {
	ID                   int64     `ksql:"id,skipInserts"                    json:"id"`
	KillChainID          int64     `ksql:"kill_chain_id"                     json:"kill_chain_id"`
	SessionID            int64     `ksql:"session_id"                        json:"session_id"`
	Phase                string    `ksql:"phase"                             json:"phase"`
	Evidence             string    `ksql:"evidence"                          json:"evidence"`
	FirstRequestID       int64     `ksql:"first_request_id"                  json:"first_request_id"`
	FirstRequestTime     time.Time `ksql:"first_request_time"                json:"first_request_time"`
	LastRequestTime      time.Time `ksql:"last_request_time"                 json:"last_request_time"`
	RequestCount         int64     `ksql:"request_count"                     json:"request_count"`
	PhaseDurationSeconds int64     `ksql:"phase_duration_seconds"            json:"phase_duration_seconds"`
	SourceModel          string    `ksql:"source_model"                      json:"source_model"`
	CreatedAt            time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt            time.Time `ksql:"updated_at,timeNowUTC"             json:"updated_at"`
}

func (k *SingleKillChainPhase) ModelID() int64 { return k.ID }
