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

type Application struct {
	ID         int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the application"`
	Name       string                   `ksql:"name" json:"name" doc:"The application name"`
	Version    *string                  `ksql:"version" json:"version" doc:"The application version"`
	Vendor     *string                  `ksql:"vendor" json:"vendor" doc:"The application vendor"`
	OS         *string                  `ksql:"os" json:"os" doc:"The OS on which the application runs"`
	Link       *string                  `ksql:"link" json:"link" doc:"A reference link"`
	CreatedAt  time.Time                `ksql:"created_at,skipInserts,skipUpdates" yaml:"created_at" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt  time.Time                `ksql:"updated_at,timeNowUTC" json:"updated_at" yaml:"updated_at" doc:"Date and time of last update"`
	ExtVersion int64                    `ksql:"ext_version" json:"ext_version" yaml:"ext_version" doc:"The external numerical version"`
	ExtUuid    string                   `ksql:"ext_uuid" json:"ext_uuid" yaml:"ext_uuid" doc:"The external unique ID"`
	CVES       pgtype.FlatArray[string] `ksql:"cves" json:"cves" yaml:"cves" doc:"Related Mitre CVEs"`
}

func (c *Application) ModelID() int64              { return c.ID }
func (c *Application) ExternalVersion() int64      { return c.ExtVersion }
func (c *Application) ExternalUuid() string        { return c.ExtUuid }
func (c *Application) SetModelID(id int64)         { c.ID = id }
func (c *Application) SetExternalUuid(uuid string) { c.ExtUuid = uuid }
