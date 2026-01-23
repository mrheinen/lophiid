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

// The request purpose for the ContentRule needs to be kept in sync with the
// database REQUEST_PURPOSE type.
const (
	RuleRequestPurposeUnknown = "UNKNOWN"
	RuleRequestPurposeAttack  = "ATTACK"
	RuleRequestPurposeRecon   = "RECON"
	RuleRequestPurposeCrawl   = "CRAWL"
)

type ContentRule struct {
	ID           int64                 `ksql:"id,skipInserts" json:"id" doc:"The rule ID"`
	Uri          string                `ksql:"uri" json:"uri"           doc:"The URI matching string"`
	Body         string                `ksql:"body" json:"body"         doc:"The body matching string"`
	Method       string                `ksql:"method" json:"method"     doc:"The HTTP method the rule matches on"`
	Port         int64                 `ksql:"port" json:"port"         doc:"The TCP port the rule matches on (deprecated)"`
	Ports        pgtype.FlatArray[int] `ksql:"ports" json:"ports" doc:"The TCP ports the rule matches on"`
	UriMatching  string                `ksql:"uri_matching" json:"uri_matching" yaml:"uri_matching"   doc:"The URI matching method (exact, regex, ..)"`
	BodyMatching string                `ksql:"body_matching" json:"body_matching" yaml:"body_matching" doc:"The body matching method"`
	ContentID    int64                 `ksql:"content_id" json:"content_id" yaml:"content_id" doc:"The ID of the Content this rule serves"`
	AppID        int64                 `ksql:"app_id" json:"app_id"         yaml:"app_id" doc:"The ID of the application for which this rule is"`
	// The content and app UUID are only set on imported rules.
	AppUuid      string     `ksql:"app_uuid" json:"app_uuid" yaml:"app_uuid" doc:"The external UUID of the related app"`
	ContentUuid  string     `ksql:"content_uuid" json:"content_uuid" yaml:"content_uuid" doc:"The external UUID of the related content"`
	CreatedAt    time.Time  `ksql:"created_at,skipInserts,skipUpdates" yaml:"created_at" json:"created_at" doc:"Creation date of the rule"`
	UpdatedAt    time.Time  `ksql:"updated_at,timeNowUTC" json:"updated_at" yaml:"updated_at" doc:"Last update date of the rule"`
	ValidUntil   *time.Time `ksql:"valid_until"    json:"valid_until" yaml:"valid_until" doc:"time.Time of expiration"`
	Alert        bool       `ksql:"alert" json:"alert" doc:"A bool (0 or 1) indicating if the rule should alert"`
	AllowFromNet *string    `ksql:"allow_from_net" json:"allow_from_net" doc:"The IP network range from which the rule is allowed to match (e.g. 1.1.1.1/24)"`
	Enabled      bool       `ksql:"enabled" json:"enabled" doc:"A bool (0 or 1) indicating if the rule is enabled"`
	Block        bool       `ksql:"block" json:"block" doc:"A bool (0 or 1) indicating if requests matching the rule should be blocked"`
	ExtVersion   int64      `ksql:"ext_version" json:"ext_version" yaml:"ext_version" doc:"The external numerical version of the rule"`
	ExtUuid      string     `ksql:"ext_uuid" json:"ext_uuid" yaml:"ext_uuid" doc:"The external unique ID of the rule"`
	IsTemporary  bool       `ksql:"is_temporary" json:"is_temporary" yaml:"is_temporary" doc:"A bool (0 or 1) indicating if the rule is a temporary rule"`
	// The request purpose should indicate what the request is intended to do. It
	// is used, amongst other things, to determine whether a request is malicious
	// or not.
	// Valid values are:
	//   - UNKNOWN : the purpose is unknown
	//   - RECON : the purpose is reconnaissance
	//   - CRAWL : the request is part of regular crawling
	//   - ATTACK : the request is an attack (e.g. an RCE)
	RequestPurpose   string       `ksql:"request_purpose" json:"request_purpose" yaml:"request_purpose" doc:"The purpose of the request (e.g. UNKNOWN, RECON, CRAWL, ATTACK)"`
	Responder        string       `ksql:"responder" json:"responder" doc:"The responder type for this rule (e.g. COMMAND_INJECTION)"`
	ResponderRegex   string       `ksql:"responder_regex" json:"responder_regex" yaml:"responder_regex" doc:"The responder regex to grab the relevant bits"`
	ResponderDecoder string       `ksql:"responder_decoder" json:"responder_decoder" yaml:"responder_decoder" doc:"The responder decoder to use (e.g. NONE, URI, HTML)"`
	TagsToApply      []TagPerRule `json:"tags_to_apply"`
}

func (c *ContentRule) ModelID() int64              { return c.ID }
func (c *ContentRule) ExternalVersion() int64      { return c.ExtVersion }
func (c *ContentRule) ExternalUuid() string        { return c.ExtUuid }
func (c *ContentRule) SetExternalUuid(uuid string) { c.ExtUuid = uuid }
func (c *ContentRule) SetModelID(id int64)         { c.ID = id }
