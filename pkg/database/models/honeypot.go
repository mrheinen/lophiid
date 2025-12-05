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

type Honeypot struct {
	ID                   int64                   `ksql:"id,skipInserts" json:"id" doc:"The ID of the honeypot"`
	IP                   string                  `ksql:"ip" json:"ip" doc:"The IP of the honeypot (v4 or v6)"`
	Version              string                  `ksql:"version" json:"version" doc:"The honeypot version"`
	AuthToken            string                  `ksql:"auth_token" json:"auth_token" doc:"The authentication token"`
	CreatedAt            time.Time               `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt            time.Time               `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	LastCheckin          time.Time               `ksql:"last_checkin,skipInserts,skipUpdates" json:"last_checkin" doc:"Date and time of last seen"`
	DefaultContentID     int64                   `ksql:"default_content_id" json:"default_content_id" doc:"The Content ID that is served by default"`
	RequestsCountLastDay int64                   `json:"request_count_last_day"`
	Ports                pgtype.FlatArray[int64] `ksql:"ports" json:"ports" doc:"HTTP ports that the honeypot listens on"`
	SSLPorts             pgtype.FlatArray[int64] `ksql:"ssl_ports" json:"ssl_ports" doc:"HTTPS ports that the honeypot listens on"`
	RuleGroupID          int64                   `ksql:"rule_group_id" json:"rule_group_id" doc:"The ID of the rule group"`
}

func (c *Honeypot) ModelID() int64 { return c.ID }
