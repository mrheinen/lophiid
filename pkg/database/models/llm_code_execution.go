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
package models

import (
	"time"
)

type LLMCodeExecution struct {
	ID          int64     `ksql:"id,skipInserts" json:"id" doc:"Database ID for this entry"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Creation date of the context in the database"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	SessionID   int64     `ksql:"session_id" json:"session_id" doc:"Database ID for the session"`
	RequestID   int64     `ksql:"request_id" json:"request_id" doc:"Database ID for the request"`
	Stdout      []byte    `ksql:"stdout" json:"stdout" doc:"Output of the AI"`
	Snippet     []byte    `ksql:"snippet" json:"snippet" doc:"The code snippet"`
	Language    string    `ksql:"language" json:"language" doc:"The language of the code"`
	SourceModel string    `ksql:"source_model" json:"source_model" doc:"The model responsible for the execution"`
	Headers     string    `ksql:"headers" json:"headers" doc:"The headers of the code"`
}

func (s *LLMCodeExecution) ModelID() int64 { return s.ID }
