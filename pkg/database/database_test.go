// Lophiid distributed honeypot
// Copyright (C) 2023-2025 Niels Heinen
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
package database

import (
	"strings"
	"testing"
	"time"

	"lophiid/pkg/database/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBatchInsertQuery_EmptySlice(t *testing.T) {
	_, _, err := BuildBatchInsertQuery("campaign_request", []models.DataModel{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty model slice")
}

func TestBuildBatchInsertQuery_SingleRow(t *testing.T) {
	dms := []models.DataModel{
		&models.CampaignRequest{
			CampaignID: 10,
			RequestID:  20,
			Role:       "seed",
		},
	}

	query, params, err := BuildBatchInsertQuery("campaign_request", dms)
	require.NoError(t, err)

	assert.Contains(t, query, "INSERT INTO campaign_request")
	assert.Contains(t, query, "campaign_id")
	assert.Contains(t, query, "request_id")
	assert.Contains(t, query, "role")
	assert.Contains(t, query, "added_at")
	// Should not contain the skipInserts field "id".
	assert.NotContains(t, query, "(id,")
	assert.NotContains(t, query, " id,")

	// 4 insertable fields: campaign_id, request_id, role, added_at
	assert.Equal(t, 4, len(params))
	assert.Equal(t, int64(10), params[0])
	assert.Equal(t, int64(20), params[1])
	assert.Equal(t, "seed", params[2])
	// added_at should be a time.Time (skipUpdates field, not skipInserts).
	_, ok := params[3].(time.Time)
	assert.True(t, ok, "added_at param should be time.Time")

	// Verify placeholder numbering.
	assert.Contains(t, query, "($1, $2, $3, $4)")
}

func TestBuildBatchInsertQuery_MultipleRows(t *testing.T) {
	dms := []models.DataModel{
		&models.CampaignRequest{
			CampaignID: 10,
			RequestID:  20,
			Role:       "seed",
		},
		&models.CampaignRequest{
			CampaignID: 10,
			RequestID:  30,
			Role:       "correlated",
		},
		&models.CampaignRequest{
			CampaignID: 10,
			RequestID:  40,
			Role:       "seed",
		},
	}

	query, params, err := BuildBatchInsertQuery("campaign_request", dms)
	require.NoError(t, err)

	// 4 fields * 3 rows = 12 params
	assert.Equal(t, 12, len(params))

	// Check placeholder numbering for all three rows.
	assert.Contains(t, query, "($1, $2, $3, $4)")
	assert.Contains(t, query, "($5, $6, $7, $8)")
	assert.Contains(t, query, "($9, $10, $11, $12)")

	// Verify values for second row.
	assert.Equal(t, int64(10), params[4])
	assert.Equal(t, int64(30), params[5])
	assert.Equal(t, "correlated", params[6])
}

func TestBuildBatchInsertQuery_TimeNowUTCField(t *testing.T) {
	dms := []models.DataModel{
		&models.Tag{
			Name:        "test-tag",
			ColorHtml:   "#ff0000",
			Description: "a test tag",
		},
	}

	before := time.Now().UTC()
	query, params, err := BuildBatchInsertQuery("tag", dms)
	after := time.Now().UTC()
	require.NoError(t, err)

	assert.Contains(t, query, "INSERT INTO tag")
	// updated_at is tagged timeNowUTC, so it should be auto-filled.
	assert.Contains(t, query, "updated_at")
	// id and created_at are skipInserts, should not appear.
	assert.False(t, strings.HasPrefix(query, "INSERT INTO tag (id,"))

	// Find the updated_at param (last one for a Tag: name, color_html, description, updated_at).
	require.True(t, len(params) >= 4)
	ts, ok := params[len(params)-1].(time.Time)
	assert.True(t, ok, "timeNowUTC field should produce time.Time param")
	assert.False(t, ts.Before(before), "timestamp should be >= before")
	assert.False(t, ts.After(after), "timestamp should be <= after")
}

func TestBuildBatchInsertQuery_SkipsInsertFields(t *testing.T) {
	dms := []models.DataModel{
		&models.CampaignRequest{
			ID:         999,
			CampaignID: 1,
			RequestID:  2,
			Role:       "seed",
		},
	}

	query, params, err := BuildBatchInsertQuery("campaign_request", dms)
	require.NoError(t, err)

	// The ID field (skipInserts) value 999 should not appear in params.
	for _, p := range params {
		if v, ok := p.(int64); ok {
			assert.NotEqual(t, int64(999), v, "skipInserts field value should not be in params")
		}
	}

	// The column list should not contain "id" as a standalone column.
	colStart := strings.Index(query, "(")
	colEnd := strings.Index(query, ")")
	colSection := query[colStart+1 : colEnd]
	for _, col := range strings.Split(colSection, ",") {
		assert.NotEqual(t, "id", strings.TrimSpace(col), "skipInserts column 'id' should not appear")
	}
}
