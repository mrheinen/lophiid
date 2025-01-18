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

type Yara struct {
	ID                int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the yara entry"`
	DownloadID        int64                    `ksql:"download_id" json:"download_id" doc:"The ID of the download the yara entry belongs to"`
	Identifier        string                   `ksql:"identifier" json:"identifier" doc:"The identifier of the yara entry"`
	Author            string                   `ksql:"author" json:"author" doc:"The author of the yara entry"`
	Description       string                   `ksql:"description" json:"description" doc:"The description of the yara entry"`
	Reference         string                   `ksql:"reference" json:"reference" doc:"The metadata reference"`
	Date              string                   `ksql:"date" json:"date" doc:"The metadata date"`
	EID               string                   `ksql:"eid" json:"eid" doc:"The metadata ID"`
	MalpediaReference string                   `ksql:"malpedia_reference" json:"malpedia_reference" doc:"The malpedia link"`
	MalpediaLicense   string                   `ksql:"malpedia_license" json:"malpedia_license" doc:"The malpedia license"`
	MalpediaSharing   string                   `ksql:"malpedia_sharing" json:"malpedia_sharing" doc:"The malpedia sharing tlp"`
	Metadata          pgtype.FlatArray[string] `ksql:"metadata" json:"metadata" doc:"The metadata of the yara entry"`
	Tags              pgtype.FlatArray[string] `ksql:"tags" json:"tags" doc:"The tags of the yara entry"`
	CreatedAt         time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"The date and time of creation"`
	UpdatedAt         time.Time                `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"The date and time of last update"`
}

func (c *Yara) ModelID() int64 { return c.ID }
