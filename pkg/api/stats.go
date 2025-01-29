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

type GlobalStatisticsResult struct {
	RequestsPerMonth   []RequestsPerMonthResult `json:"requests_per_month"`
	RequestsPerDay     []RequestsPerDayResult   `json:"requests_per_day"`
	DownloadsPerDay    []DownloadsPerDayResult  `json:"downloads_per_day"`
	MethodsLast24Hours []MethodCountResult      `json:"methods_last_24_hours"`
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

	return finalResult, nil
}
