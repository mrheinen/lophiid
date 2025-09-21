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
)

type SessionExecutionContext struct {
	ID          int64     `ksql:"id,skipInserts" json:"id" doc:"Database ID for this entry"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Creation date of the context in the database"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	SessionID   int64     `ksql:"session_id" json:"session_id" doc:"Database ID for the session"`
	RequestID   int64     `ksql:"request_id" json:"request_id" doc:"Database ID for the request"`
	EnvHostname string    `ksql:"env_hostname" json:"env_hostname" doc:"Hostname of the environment"`
	EnvUser     string    `ksql:"env_user" json:"env_user" doc:"User of the environment"`
	EnvCWD      string    `ksql:"env_cwd" json:"env_cwd" doc:"Working directory of the environment"`
	Input       string    `ksql:"input" json:"input" doc:"Input given to the AI"`
	Output      string    `ksql:"output" json:"output" doc:"Output of the AI"`
	Summary     string    `ksql:"summary" json:"summary" doc:"Summary of the AI's response"`
	SourceModel string    `ksql:"source_model" json:"source_model" doc:"The model used to generate the AI data"`
}

func (s *SessionExecutionContext) ModelID() int64 { return s.ID }
