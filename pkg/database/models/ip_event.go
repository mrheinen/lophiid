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

type IpEvent struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	IP          string    `ksql:"ip" json:"ip" doc:"The source IP"`
	HoneypotIP  string    `ksql:"honeypot_ip" json:"honeypot_ip" doc:"The honeypot IP"`
	Domain      string    `ksql:"domain" json:"domain" doc:"The domain for the IP"`
	Type        string    `ksql:"type" json:"type" doc:"The type of event (e.g. ATTACKED, CRAWLED)"`
	Subtype     string    `ksql:"subtype" json:"subtype" doc:"The subtype of the event (e.g. RCE, LFI)"`
	Details     string    `ksql:"details" json:"details" doc:"Any additional details about the event"`
	Note        string    `ksql:"note" json:"note"`
	Count       int64     `ksql:"count" json:"count" doc:"How often this event was seen"`
	RequestID   int64     `ksql:"request_id" json:"request_id" doc:"The ID of a request related to the event"`
	FirstSeenAt time.Time `ksql:"first_seen_at,skipUpdates" json:"first_seen_at" doc:"When the event was first seen"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"When the event was created in the database"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Last time the event was updated"`
	Source      string    `ksql:"source" json:"source" doc:"The source of the event"`
	SourceRef   string    `ksql:"source_ref" json:"source_ref" doc:"A reference related to the source of the event"`
}

func (c *IpEvent) ModelID() int64 { return c.ID }
