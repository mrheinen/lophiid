// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
package campaign

import (
	"encoding/json"
	"testing"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeAggregationState_NoLinks(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		CampaignRequestsToReturn: []models.CampaignRequest{},
	}

	state, err := ComputeAggregationState(fakeDB, 1)
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, 0, state.Behavior.TotalRequests)
}

func TestComputeAggregationState_SingleSeed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	fakeDB := &database.FakeDatabaseClient{
		CampaignRequestsToReturn: []models.CampaignRequest{
			{ID: 1, CampaignID: 10, RequestID: 100, Role: constants.CampaignRequestRoleSeed},
		},
		RequestToReturn: models.Request{
			ID:           100,
			SourceIP:     "1.2.3.4",
			Uri:          "/exploit",
			Method:       "POST",
			CmpHash:      "abc123",
			Body:         []byte("malicious payload"),
			TimeReceived: now,
		},
		RequestDescriptionsToReturn: []models.RequestDescription{
			{
				CmpHash:             "abc123",
				AIApplication:       "Apache Struts",
				AIVulnerabilityType: "RCE",
				AIMitreAttack:       "T1190",
				AICVE:               "CVE-2017-5638",
			},
		},
		P0fResultToReturn: models.P0fResult{
			OsName:    "Linux",
			OsVersion: "3.x",
		},
		DownloadsToReturn: []models.Download{},
	}

	state, err := ComputeAggregationState(fakeDB, 10)
	require.NoError(t, err)

	// Timeline.
	assert.Equal(t, now.Format(time.RFC3339), state.Timeline.FirstSeen)
	assert.Equal(t, now.Format(time.RFC3339), state.Timeline.LastSeen)
	assert.Equal(t, 1, state.Timeline.ActiveDays)

	day := now.Format("2006-01-02")
	assert.Equal(t, 1, state.Timeline.ActivityHistogram[day])

	// Sources.
	assert.Contains(t, state.Sources.UniqueIPs, "1.2.3.4")

	// Attack profile.
	assert.Contains(t, state.AttackProfile.TargetedApps, "Apache Struts")
	assert.Contains(t, state.AttackProfile.VulnerabilityTypes, "RCE")
	assert.Contains(t, state.AttackProfile.MITRETechniques, "T1190")
	assert.Contains(t, state.AttackProfile.CVEs, "CVE-2017-5638")
	assert.Equal(t, 1, state.AttackProfile.UniquePayloadHashes)
	assert.Equal(t, 1, len(state.AttackProfile.TopURIs))
	assert.Equal(t, "/exploit", state.AttackProfile.TopURIs[0].URI)
	assert.Equal(t, 1, state.AttackProfile.TopURIs[0].Count)

	// Behavior.
	assert.Equal(t, 1, state.Behavior.TotalRequests)
	assert.Equal(t, 1, state.Behavior.MaliciousSeedCount)
	assert.Equal(t, 0, state.Behavior.CorrelatedReconCount)
	assert.Equal(t, 1, state.Behavior.HTTPMethods["POST"])

	// Sample payloads.
	assert.Equal(t, 1, len(state.AttackProfile.SamplePayloads))
	assert.Equal(t, "malicious payload", state.AttackProfile.SamplePayloads[0])

	// OS fingerprints.
	assert.Equal(t, 1, len(state.OSFingerprints))
	assert.Equal(t, "Linux 3.x", state.OSFingerprints[0].OS)
}

func TestComputeAggregationState_MixedRoles(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	fakeDB := &database.FakeDatabaseClient{
		CampaignRequestsToReturn: []models.CampaignRequest{
			{ID: 1, CampaignID: 10, RequestID: 100, Role: constants.CampaignRequestRoleSeed},
			{ID: 2, CampaignID: 10, RequestID: 101, Role: constants.CampaignRequestRoleCorrelated},
			{ID: 3, CampaignID: 10, RequestID: 102, Role: constants.CampaignRequestRoleSeed},
		},
		RequestToReturn: models.Request{
			ID:           100,
			SourceIP:     "1.2.3.4",
			Uri:          "/test",
			Method:       "GET",
			TimeReceived: now,
		},
		DownloadsToReturn: []models.Download{},
		P0fErrorToReturn:  assert.AnError,
	}

	state, err := ComputeAggregationState(fakeDB, 10)
	require.NoError(t, err)

	// FakeDB returns the same request for all GetRequestByID calls,
	// so all 3 links resolve to the same request data.
	assert.Equal(t, 3, state.Behavior.TotalRequests)
	assert.Equal(t, 2, state.Behavior.MaliciousSeedCount)
	assert.Equal(t, 1, state.Behavior.CorrelatedReconCount)
}

func TestComputeAggregationState_WithDownloads(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	fakeDB := &database.FakeDatabaseClient{
		CampaignRequestsToReturn: []models.CampaignRequest{
			{ID: 1, CampaignID: 10, RequestID: 100, Role: constants.CampaignRequestRoleSeed},
		},
		RequestToReturn: models.Request{
			ID:           100,
			SourceIP:     "1.2.3.4",
			Uri:          "/dl",
			Method:       "GET",
			TimeReceived: now,
		},
		DownloadsToReturn: []models.Download{
			{
				RequestID:            100,
				SHA256sum:            "deadbeef",
				VTAnalysisMalicious:  10,
				VTAnalysisSuspicious: 2,
				VTAnalysisHarmless:   50,
			},
		},
		P0fErrorToReturn: assert.AnError,
	}

	state, err := ComputeAggregationState(fakeDB, 10)
	require.NoError(t, err)

	assert.True(t, state.Behavior.HasDownloads)
	assert.Equal(t, 1, state.Behavior.DownloadCount)
	assert.Contains(t, state.Behavior.DownloadVerdicts, "malicious")

	require.Equal(t, 1, len(state.VTScanResults))
	assert.Equal(t, "deadbeef", state.VTScanResults[0].SHA256)
	assert.Equal(t, int64(10), state.VTScanResults[0].VTMalicious)
	assert.Equal(t, int64(2), state.VTScanResults[0].VTSuspicious)
	assert.Equal(t, int64(50), state.VTScanResults[0].VTHarmless)
}

func TestComputeAggregationState_DownloadFilteredByCampaign(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	fakeDB := &database.FakeDatabaseClient{
		CampaignRequestsToReturn: []models.CampaignRequest{
			{ID: 1, CampaignID: 10, RequestID: 100, Role: constants.CampaignRequestRoleSeed},
		},
		RequestToReturn: models.Request{
			ID:           100,
			SourceIP:     "1.2.3.4",
			Uri:          "/test",
			Method:       "GET",
			TimeReceived: now,
		},
		DownloadsToReturn: []models.Download{
			{RequestID: 999, SHA256sum: "should-not-appear", VTAnalysisMalicious: 5},
		},
		P0fErrorToReturn: assert.AnError,
	}

	state, err := ComputeAggregationState(fakeDB, 10)
	require.NoError(t, err)

	assert.False(t, state.Behavior.HasDownloads, "download for request 999 not in campaign should be filtered out")
	assert.Equal(t, 0, state.Behavior.DownloadCount)
}

func TestComputeAggregationState_DBError(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ErrorToReturn: assert.AnError,
	}

	_, err := ComputeAggregationState(fakeDB, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fetching campaign_request links")
}

func TestAggregationState_ToJSON(t *testing.T) {
	state := &AggregationState{
		Timeline: TimelineSection{
			FirstSeen:         "2025-01-01T00:00:00Z",
			LastSeen:          "2025-01-02T00:00:00Z",
			ActiveDays:        2,
			ActivityHistogram: map[string]int{"2025-01-01": 5, "2025-01-02": 3},
		},
		Behavior: BehaviorSection{
			TotalRequests:      8,
			MaliciousSeedCount: 5,
			HTTPMethods:        map[string]int{"GET": 3, "POST": 5},
		},
	}

	jsonBytes, err := state.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonBytes)

	// Verify round-trip.
	var parsed AggregationState
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)
	assert.Equal(t, 2, parsed.Timeline.ActiveDays)
	assert.Equal(t, 8, parsed.Behavior.TotalRequests)
	assert.Equal(t, 5, parsed.Timeline.ActivityHistogram["2025-01-01"])
}

func TestCappedStringSet(t *testing.T) {
	set := map[string]bool{
		"a": true,
		"b": true,
		"c": true,
		"d": true,
		"e": true,
	}

	result := cappedStringSet(set, 3)
	assert.Equal(t, 3, len(result))
}

func TestCappedStringSet_EmptySet(t *testing.T) {
	result := cappedStringSet(map[string]bool{}, 10)
	assert.Equal(t, 0, len(result))
}

func TestCappedStringSet_UnderLimit(t *testing.T) {
	set := map[string]bool{"x": true, "y": true}
	result := cappedStringSet(set, 10)
	assert.Equal(t, 2, len(result))
}
