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

type P0fResult struct {
	ID               int64     `ksql:"id,skipInserts" json:"id"`
	IP               string    `ksql:"ip" json:"ip"`
	FirstSeen        time.Time `ksql:"first_seen_time" json:"first_seen_time"`
	LastSeen         time.Time `ksql:"last_seen_time" json:"last_seen_time"`
	TotalCount       int64     `ksql:"total_count" json:"total_count"`
	UptimeMinutes    int64     `ksql:"uptime_minutes" json:"uptime_minutes"`
	UptimeDays       int64     `ksql:"uptime_days" json:"uptime_days"`
	Distance         int64     `ksql:"distance" json:"distance"`
	LastNatDetection time.Time `ksql:"last_nat_detection_time" json:"last_nat_detection_time"`
	LastOsChange     time.Time `ksql:"last_os_change_time" json:"last_os_change_time"`
	OsMatchQuality   int64     `ksql:"os_match_quality" json:"os_match_quality"`
	OsName           string    `ksql:"os_name" json:"os_name"`
	OsVersion        string    `ksql:"os_version" json:"os_version"`
	HttpName         string    `ksql:"http_name" json:"http_name"`
	HttpFlavor       string    `ksql:"http_flavor" json:"http_flavor"`
	Language         string    `ksql:"language" json:"language"`
	LinkType         string    `ksql:"link_type" json:"link_type"`
	CreatedAt        time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt        time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *P0fResult) ModelID() int64 { return c.ID }
