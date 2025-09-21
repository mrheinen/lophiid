// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.

package database

import (
	"lophiid/pkg/database/models"

	"github.com/vingarcia/ksql"
)

// SearchConfig defines the configuration for a generic search operation
type SearchConfig struct {
	Table         *ksql.Table
	TableName     string
	AllowedFields []string
	OrderBy       string
}

var contentConfig = SearchConfig{
	Table:         &ContentTable,
	TableName:     "content",
	AllowedFields: getDatamodelDatabaseFields(models.Content{}),
	OrderBy:       "id DESC",
}

var sessionContextConfig = SearchConfig{
	Table:         &SessionContextTable,
	TableName:     "session_execution_context",
	AllowedFields: getDatamodelDatabaseFields(models.SessionExecutionContext{}),
	OrderBy:       "id DESC",
}

var yaraConfig = SearchConfig{
	Table:         &YaraTable,
	TableName:     "yara",
	AllowedFields: getDatamodelDatabaseFields(models.Yara{}),
	OrderBy:       "id DESC",
}

var contentRulesConfig = SearchConfig{
	Table:         &ContentRuleTable,
	TableName:     "content_rule",
	AllowedFields: getDatamodelDatabaseFields(models.ContentRule{}),
	OrderBy:       "updated_at DESC",
}

var eventsConfig = SearchConfig{
	Table:         &IpEventTable,
	TableName:     "ip_event",
	AllowedFields: getDatamodelDatabaseFields(models.IpEvent{}),
	OrderBy:       "id DESC",
}

var sessionConfig = SearchConfig{
	Table:         &SessionTable,
	TableName:     "session",
	AllowedFields: getDatamodelDatabaseFields(models.Session{}),
	OrderBy:       "started_at DESC",
}

var requestDescriptionConfig = SearchConfig{
	Table:         &RequestDescriptionTable,
	TableName:     "request_description",
	AllowedFields: getDatamodelDatabaseFields(models.RequestDescription{}),
	OrderBy:       "created_at DESC",
}

var appsConfig = SearchConfig{
	Table:         &AppTable,
	TableName:     "app",
	AllowedFields: getDatamodelDatabaseFields(models.Application{}),
	OrderBy:       "updated_at DESC",
}

var downloadsConfig = SearchConfig{
	Table:         &DownloadTable,
	TableName:     "downloads",
	AllowedFields: getDatamodelDatabaseFields(models.Download{}),
	OrderBy:       "last_seen_at DESC",
}

var honeypotConfig = SearchConfig{
	Table:         &HoneypotTable,
	TableName:     "honeypot",
	AllowedFields: getDatamodelDatabaseFields(models.Honeypot{}),
	OrderBy:       "last_checkin DESC",
}

var storedQueryConfig = SearchConfig{
	Table:         &StoredQueryTable,
	TableName:     "stored_query",
	AllowedFields: getDatamodelDatabaseFields(models.StoredQuery{}),
	OrderBy:       "updated_at DESC",
}

var tagsConfig = SearchConfig{
	Table:         &TagTable,
	TableName:     "tag",
	AllowedFields: getDatamodelDatabaseFields(models.Tag{}),
	OrderBy:       "updated_at DESC",
}

var whoisConfig = SearchConfig{
	Table:         &WhoisTable,
	TableName:     "whois",
	AllowedFields: getDatamodelDatabaseFields(models.Whois{}),
	OrderBy:       "id DESC",
}

var tagPerQueryConfig = SearchConfig{
	Table:         &TagPerQueryTable,
	TableName:     "tag_per_query",
	AllowedFields: getDatamodelDatabaseFields(models.TagPerQuery{}),
	OrderBy:       "",
}

var tagPerRequestConfig = SearchConfig{
	Table:         &TagPerRequestTable,
	TableName:     "tag_per_request",
	AllowedFields: getDatamodelDatabaseFields(models.TagPerRequest{}),
	OrderBy:       "",
}
