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
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

type KillChain struct {
	ID               int64                    `ksql:"id,skipInserts"            json:"id"`
	SessionID        int64                    `ksql:"session_id"                json:"session_id"`
	StartedAt        time.Time                `ksql:"started_at"                json:"started_at"`
	UniqueBaseHashes pgtype.FlatArray[string] `ksql:"unique_base_hashes"            json:"unique_base_hashes"`
	SourceModel      string                   `ksql:"source_model"                  json:"source_model"`
	PhaseCount       int64                    `ksql:"phase_count"               json:"phase_count"`
	MaxPhaseDepth    int64                    `ksql:"max_phase_depth"           json:"max_phase_depth"`
	CreatedAt        time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt        time.Time                `ksql:"updated_at,timeNowUTC"     json:"updated_at"`
}

func (k *KillChain) ModelID() int64 { return k.ID }
