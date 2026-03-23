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

type CampaignRequest struct {
	ID         int64     `ksql:"id,skipInserts" json:"id" doc:"The ID of the campaign request link"`
	CampaignID int64     `ksql:"campaign_id" json:"campaign_id" doc:"The campaign this request belongs to"`
	RequestID  int64     `ksql:"request_id" json:"request_id" doc:"The request associated with the campaign"`
	Role       string    `ksql:"role" json:"role" doc:"Role of the request: seed (malicious) or correlated (non-malicious)"`
	AddedAt    time.Time `ksql:"added_at,skipUpdates" json:"added_at" doc:"When the request was associated with this campaign"`
}

func (c *CampaignRequest) ModelID() int64 { return c.ID }
