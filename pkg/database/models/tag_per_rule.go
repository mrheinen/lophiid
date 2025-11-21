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

type TagPerRule struct {
	ID        int64     `ksql:"id,skipInserts" json:"id"`
	TagID     int64     `ksql:"tag_id" json:"tag_id"`
	RuleID    int64     `ksql:"rule_id" json:"rule_id"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"The date and time of creation"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"The date and time of the last update"`
}

func (c *TagPerRule) ModelID() int64 { return c.ID }
