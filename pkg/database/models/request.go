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

type Request struct {
	ID             int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the request"`
	Proto          string                   `ksql:"proto" json:"proto" doc:"The HTTP protocol (e.g. HTTP/1.0)"`
	Host           string                   `ksql:"host" json:"host" doc:"The HTTP Host header value"`
	Port           int64                    `ksql:"port" json:"port" doc:"The HTTP server port"`
	Method         string                   `ksql:"method" json:"method" doc:"The HTTP method (e.g. GET, POST, PUT, DELETE, ...)"`
	Uri            string                   `ksql:"uri" json:"uri" doc:"The request URI"`
	Path           string                   `ksql:"path" json:"path" doc:"The URL path"`
	Query          string                   `ksql:"query" json:"query" doc:"The query section of the URL"`
	Referer        string                   `ksql:"referer" json:"referer" doc:"The referer header value"`
	ContentType    string                   `ksql:"content_type" json:"content_type" doc:"The Content-Type header value"`
	ContentLength  int64                    `ksql:"content_length" json:"content_length" doc:"The Content-Length header value"`
	UserAgent      string                   `ksql:"user_agent" json:"user_agent" doc:"The User-Agent value"`
	Headers        pgtype.FlatArray[string] `ksql:"headers" json:"headers" doc:"The client HTTP headers"`
	Body           []byte                   `ksql:"body" json:"body" doc:"The request body"`
	HoneypotIP     string                   `ksql:"honeypot_ip" json:"honeypot_ip" doc:"The honeypot IP that received the request"`
	SourceIP       string                   `ksql:"source_ip" json:"source_ip" doc:"The HTTP client source IP"`
	SourcePort     int64                    `ksql:"source_port" json:"source_port" doc:"The HTTP client source port"`
	Raw            string                   `ksql:"raw" json:"raw" doc:"The raw HTTP request"`
	RawResponse    string                   `ksql:"raw_response" json:"raw_response" doc:"The raw HTTP response (only used for scripted Content)"`
	TimeReceived   time.Time                `ksql:"time_received,skipUpdates" json:"time_received" doc:"The date and time the honeypot received the request"`
	CreatedAt      time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"The date and time of creation"`
	UpdatedAt      time.Time                `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"The date and time of the last update"`
	ContentID      int64                    `ksql:"content_id" json:"content_id" doc:"The Content ID that was served"`
	SessionID      int64                    `ksql:"session_id" json:"session_id" doc:"The session ID of the request"`
	AppID          int64                    `ksql:"app_id" json:"app_id" doc:"The App ID of the rule that matched this request"`
	ContentDynamic bool                     `ksql:"content_dynamic" json:"content_dynamic" doc:"A bool indicating if the Content is dynamic (script based)"`
	RuleID         int64                    `ksql:"rule_id" json:"rule_id" doc:"The ID of the rule that matched this request"`
	RuleUuid       string                   `ksql:"rule_uuid" json:"rule_uuid" doc:"The UUID of the rule that matched this request"`
	Starred        bool                     `ksql:"starred" json:"starred" doc:"A bool if the request is starred"`
	BaseHash       string                   `ksql:"base_hash" json:"base_hash" doc:"A base hash to find roughly similar requests"`
	CmpHash        string                   `ksql:"cmp_hash" json:"cmp_hash" doc:"A hash to compare request across hosts"`
	Tags           []TagPerRequestFull      `json:"tags"`
	P0fResult      P0fResult                `json:"p0f_result"`
}

func (c *Request) ModelID() int64 { return c.ID }

// BodyString returns the body as a string and is used in the javascript
// context for easy access.
func (c *Request) BodyString() string { return string(c.Body) }

// SetBodyString sets the body from a string.
func (c *Request) SetBodyString(body string) { c.Body = []byte(body) }
