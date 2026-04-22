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

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// RuleManagementLog records every automated action taken by the rule generation
// and management agents against a ContentRule.
type RuleManagementLog struct {
	ID           int64                    `ksql:"id,skipInserts"                     json:"id"`
	CreatedAt    time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	Type         string                   `ksql:"type"                               json:"type"`
	RuleID       int64                    `ksql:"rule_id"                            json:"rule_id"`
	RequestID    *int64                   `ksql:"request_id"                         json:"request_id,omitempty"`
	Description  string                   `ksql:"description"                        json:"description"`
	RelatedLinks pgtype.FlatArray[string] `ksql:"related_links"                      json:"related_links"`
}

func (r *RuleManagementLog) ModelID() int64      { return r.ID }
func (r *RuleManagementLog) SetModelID(id int64) { r.ID = id }
