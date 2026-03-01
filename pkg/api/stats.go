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
package api

import (
	"fmt"
	"lophiid/pkg/database"
	"time"
)

type RequestsPerMonthResult struct {
	Month        string `ksql:"month" json:"month"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
}

type RequestsPerDayResult struct {
	Day          string `ksql:"day" json:"day"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
}

type RequestsPerDayPerMethodResult struct {
	Day          string `ksql:"day" json:"day"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
	Method       string `ksql:"method" json:"method"`
}

type DownloadsPerDayResult struct {
	Day          string `ksql:"day" json:"day"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
}

type MethodCountResult struct {
	Day          string `ksql:"day" json:"day"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
	Method       string `ksql:"method" json:"method"`
}

type Top10SourceIPs struct {
	TotalRequests int    `ksql:"total_requests" json:"total_requests"`
	SourceIP      string `ksql:"source_ip" json:"source_ip"`
}

type Top10URI struct {
	TotalRequests int    `ksql:"total_requests" json:"total_requests"`
	URI           string `ksql:"uri" json:"uri"`
}

type TriagePayloadTypeCount struct {
	TotalRequests     int    `ksql:"total_requests" json:"total_requests"`
	TriagePayloadType string `ksql:"triage_payload_type" json:"triage_payload_type"`
}

type MalwareCountResult struct {
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
	Type         string `ksql:"type" json:"type"`
	SubType      string `ksql:"subtype" json:"subtype"`
}

type GlobalStatisticsResult struct {
	RequestsPerMonth          []RequestsPerMonthResult `json:"requests_per_month"`
	RequestsPerDay            []RequestsPerDayResult   `json:"requests_per_day"`
	DownloadsPerDay           []DownloadsPerDayResult  `json:"downloads_per_day"`
	MethodsLast24Hours        []MethodCountResult      `json:"methods_last_24_hours"`
	Top10SourceIPsLast24Hours []Top10SourceIPs         `json:"top_10_source_ips_last_24_hours"`
	Top10URIsLast24Hours      []Top10URI               `json:"top_10_uris_last_24_hours"`
	Top10URIsCodeExecution    []Top10URI               `json:"top_10_uris_code_execution"`
	Top10URIsShellCommand     []Top10URI               `json:"top_10_uris_shell_command"`
	TriagePayloadTypeCounts   []TriagePayloadTypeCount `json:"triage_payload_type_counts"`
	MalwareLast24Hours        []MalwareCountResult     `json:"malware_last_24_hours"`
}

// URIStatsSummary holds the first/last seen times, first requester IP and total count.
type URIStatsSummary struct {
	FirstSeen        time.Time `ksql:"first_seen" json:"first_seen"`
	LastSeen         time.Time `ksql:"last_seen" json:"last_seen"`
	FirstRequesterIP string    `ksql:"first_requester_ip" json:"first_requester_ip"`
	TotalRequests    int       `ksql:"total_requests" json:"total_requests"`
}

// URIStatsPerMonth holds the request count for a single month.
type URIStatsPerMonth struct {
	Month        string `ksql:"month" json:"month"`
	TotalEntries int    `ksql:"total_entries" json:"total_entries"`
}

// URIStatsResult combines the summary and the per-month breakdown.
type URIStatsResult struct {
	LookupType  string             `json:"lookup_type"`
	LookupValue string             `json:"lookup_value"`
	HoneypotIP  string             `json:"honeypot_ip"`
	Summary     URIStatsSummary    `json:"summary"`
	PerMonth    []URIStatsPerMonth `json:"per_month"`
}

// validLookupColumns is the allowlist of column names accepted for URI stats lookups.
var validLookupColumns = map[string]bool{
	"uri":       true,
	"cmp_hash":  true,
	"base_hash": true,
}

// GetURIStatistics computes on-the-fly stats for the given lookup column and value.
// When honeypotIP is non-empty the results are narrowed to that honeypot only.
func GetURIStatistics(dbc database.DatabaseClient, lookupType string, lookupValue string, honeypotIP string) (URIStatsResult, error) {
	result := URIStatsResult{
		LookupType:  lookupType,
		LookupValue: lookupValue,
		HoneypotIP:  honeypotIP,
	}

	if !validLookupColumns[lookupType] {
		return result, fmt.Errorf("invalid lookup_type %q: must be uri, cmp_hash, or base_hash", lookupType)
	}

	// Build optional honeypot clause and params list.
	honeypotClause := ""
	params := []any{lookupValue}
	if honeypotIP != "" {
		honeypotClause = " AND honeypot_ip = $2"
		params = append(params, honeypotIP)
	}

	summaryQuery := fmt.Sprintf(database.QueryURIStatsSummaryTemplate, lookupType, honeypotClause, lookupType, honeypotClause)
	var summaryRows []URIStatsSummary
	if _, err := dbc.ParameterizedQuery(summaryQuery, &summaryRows, params...); err != nil {
		return result, fmt.Errorf("failed to get URI stats summary: %w", err)
	}
	if len(summaryRows) > 0 {
		result.Summary = summaryRows[0]
	}

	perMonthQuery := fmt.Sprintf(database.QueryURIStatsPerMonthTemplate, lookupType, honeypotClause)
	if _, err := dbc.ParameterizedQuery(perMonthQuery, &result.PerMonth, params...); err != nil {
		return result, fmt.Errorf("failed to get URI stats per month: %w", err)
	}

	return result, nil
}

func GetGlobalStatistics(dbc database.DatabaseClient) (GlobalStatisticsResult, error) {
	finalResult := GlobalStatisticsResult{}

	_, err := dbc.SimpleQuery(database.QueryTotalRequestsPerMonthLastYear, &finalResult.RequestsPerMonth)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get total requests per month: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTotalRequestsPerDayLast7Days, &finalResult.RequestsPerDay)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get total requests per day: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTotalNewDownloadsPerDayLast7Days, &finalResult.DownloadsPerDay)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get total downloads per day: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryCountMethodsLast24Hours, &finalResult.MethodsLast24Hours)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get methods count last 24 hours: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryCountMalwareHosted24Hours, &finalResult.MalwareLast24Hours)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get malware count last 24 hours: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTop10SourcesLastDay, &finalResult.Top10SourceIPsLast24Hours)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get top 10 source IPs count last 24 hours: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTop10URILastDay, &finalResult.Top10URIsLast24Hours)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get top 10 URIs count last 24 hours: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTop10URIsCodeExecutionLastDay, &finalResult.Top10URIsCodeExecution)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get top 10 code execution URIs: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTop10URIsShellCommandLastDay, &finalResult.Top10URIsShellCommand)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get top 10 shell command URIs: %w", err)
	}

	_, err = dbc.SimpleQuery(database.QueryTriagePayloadTypeCounts, &finalResult.TriagePayloadTypeCounts)
	if err != nil {
		return finalResult, fmt.Errorf("failed to get triage payload type counts: %w", err)
	}

	return finalResult, nil
}
