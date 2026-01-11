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

type Content struct {
	ID          int64                    `ksql:"id,skipInserts" json:"id"           doc:"The ID of the content"`
	Data        YammableBytes            `ksql:"data"           json:"data"         yaml:"data,omitempty" doc:"The content data itself"`
	Name        string                   `ksql:"name"           json:"name"         doc:"The content name"`
	Description string                   `ksql:"description"    json:"description"  doc:"The content description"`
	ContentType string                   `ksql:"content_type"   json:"content_type" yaml:"content_type" doc:"The HTTP content-type"`
	Server      string                   `ksql:"server"         json:"server"       doc:"The HTTP server with which the content is served"`
	StatusCode  string                   `ksql:"status_code"    json:"status_code"  yaml:"status_code" doc:"The HTTP status code"`
	Script      string                   `ksql:"script"         json:"script"       yaml:"script,omitempty" doc:"The content script"`
	Headers     pgtype.FlatArray[string] `ksql:"headers"        json:"headers"      yaml:"headers,omitempty" doc:"The content HTTP headers"`
	CreatedAt   time.Time                `ksql:"created_at,skipInserts,skipUpdates" yaml:"created_at" json:"created_at" doc:"time.Time of creation"`
	UpdatedAt   time.Time                `ksql:"updated_at,timeNowUTC"              yaml:"updated_at" json:"updated_at" doc:"time.Time of last update"`
	ValidUntil  *time.Time               `ksql:"valid_until"    json:"valid_until" yaml:"valid_until" doc:"time.Time of expiration"`
	ExtVersion  int64                    `ksql:"ext_version" json:"ext_version" yaml:"ext_version" doc:"The external numerical version of the content"`
	ExtUuid     string                   `ksql:"ext_uuid" json:"ext_uuid" yaml:"ext_uuid" doc:"The external unique ID of the content"`
	HasCode     bool                     `ksql:"has_code" json:"has_code" yaml:"has_code" doc:"A bool (0 or 1) indicating if the content has a code snippet"`
}

func (c *Content) ModelID() int64              { return c.ID }
func (c *Content) ExternalVersion() int64      { return c.ExtVersion }
func (c *Content) ExternalUuid() string        { return c.ExtUuid }
func (c *Content) SetExternalUuid(uuid string) { c.ExtUuid = uuid }
func (c *Content) SetModelID(id int64)         { c.ID = id }
