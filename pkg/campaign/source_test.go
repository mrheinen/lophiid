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
package campaign

import (
	"context"
	"errors"
	"testing"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"

	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestSource_NameAndEnabled(t *testing.T) {
	s := &RequestSource{enabled: true}
	assert.Equal(t, constants.CampaignSourceRequest, s.Name())
	assert.True(t, s.Enabled())

	s2 := &RequestSource{enabled: false}
	assert.False(t, s2.Enabled())
}

func TestRequestSource_EnrichRequest(t *testing.T) {
	s := &RequestSource{enabled: true}
	req := &EnrichedRequest{Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestRequestDescriptionSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		RequestDescriptionsToReturn: []models.RequestDescription{
			{
				CmpHash:             "abc123",
				AIApplication:       "Apache Struts",
				AIVulnerabilityType: "RCE",
				AIMitreAttack:       "T1190",
				AICVE:               "CVE-2017-5638",
				AIMalicious:         "YES",
			},
		},
	}

	s := &RequestDescriptionSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{Features: NewFeatureSet()}
	req.Features.Set("cmp_hash", "abc123")

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Apache Struts", req.Features.Get("ai_application"))
	assert.Equal(t, "RCE", req.Features.Get("ai_vulnerability_type"))
	assert.Equal(t, "T1190", req.Features.Get("ai_mitre_attack"))
	assert.Equal(t, "CVE-2017-5638", req.Features.Get("ai_cve"))
	assert.Equal(t, "YES", req.Features.Get("ai_malicious"))
}

func TestRequestDescriptionSource_NoCmpHash(t *testing.T) {
	s := &RequestDescriptionSource{enabled: true, cache: map[string]cachedRequestDescription{}}
	req := &EnrichedRequest{Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "", req.Features.Get("ai_application"))
}

func TestRequestDescriptionSource_PreloadDBError(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ErrorToReturn: errors.New("db error"),
	}

	s := &RequestDescriptionSource{enabled: true, db: fakeDB}
	err := s.Preload(context.Background(), time.Time{}, time.Time{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "preloading request_descriptions")
}

func TestWhoisSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		WhoisModelsToReturn: []models.Whois{
			{IP: "1.2.3.4", Country: "US"},
		},
	}

	s := &WhoisSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "US", req.Features.Get("country"))
}

func TestWhoisSource_EmptyIP(t *testing.T) {
	s := &WhoisSource{enabled: true, cache: map[string]cachedWhois{}}
	req := &EnrichedRequest{SourceIP: "", Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestWhoisSource_CacheMiss(t *testing.T) {
	s := &WhoisSource{enabled: true, cache: map[string]cachedWhois{}}
	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "", req.Features.Get("country"))
}

func TestP0fSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		P0fResultsToReturn: []models.P0fResult{
			{
				IP:        "1.2.3.4",
				OsName:    "Linux",
				OsVersion: "3.x",
				LinkType:  "Ethernet",
			},
		},
	}

	s := &P0fSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Linux", req.Features.Get("os_name"))
	assert.Equal(t, "3.x", req.Features.Get("os_version"))
	assert.Equal(t, "Ethernet", req.Features.Get("link_type"))
}

func TestP0fSource_EmptyIP(t *testing.T) {
	s := &P0fSource{enabled: true, cache: map[string]cachedP0f{}}
	req := &EnrichedRequest{SourceIP: "", Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestP0fSource_CacheMiss(t *testing.T) {
	s := &P0fSource{enabled: true, cache: map[string]cachedP0f{}}
	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "", req.Features.Get("os_name"))
}

func TestIpEventSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		IpEventToReturn: models.IpEvent{
			IP:    "1.2.3.4",
			Type:  "alert",
			Count: 42,
		},
	}

	s := &IpEventSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "alert", req.Features.Get("event_type"))
	assert.Equal(t, "42", req.Features.Get("event_count"))
}

func TestIpEventSource_EmptyIP(t *testing.T) {
	s := &IpEventSource{enabled: true, cache: map[string]cachedIpEvent{}}
	req := &EnrichedRequest{SourceIP: "", Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestSessionSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                42,
			BehaviorIsHuman:   true,
			BehaviorHasBursts: false,
			RequestCount:      100,
		},
	}

	s := &SessionSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{SessionID: 42, Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "true", req.Features.Get("behavior_is_human"))
	assert.Equal(t, "false", req.Features.Get("behavior_has_bursts"))
	assert.Equal(t, "100", req.Features.Get("request_count"))
}

func TestSessionSource_ZeroSessionID(t *testing.T) {
	s := &SessionSource{enabled: true, cache: map[int64]cachedSession{}}
	req := &EnrichedRequest{SessionID: 0, Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
}

func TestDownloadsSource_EnrichRequest(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		DownloadsToReturn: []models.Download{
			{
				RequestID:           1,
				SHA256sum:           "deadbeefcafe",
				VTAnalysisMalicious: 15,
				DetectedContentType: "application/x-executable",
			},
		},
	}

	s := &DownloadsSource{enabled: true, db: fakeDB}
	require.NoError(t, s.Preload(context.Background(), time.Time{}, time.Time{}))

	req := &EnrichedRequest{RequestID: 1, Features: NewFeatureSet()}
	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "deadbeefcafe", req.Features.Get("download_sha256_hash"))
	assert.Equal(t, "15", req.Features.Get("vt_malicious_count"))
	assert.Equal(t, "application/x-executable", req.Features.Get("content_type"))
}

func TestDownloadsSource_CacheMiss(t *testing.T) {
	s := &DownloadsSource{enabled: true, cache: map[int64]cachedDownload{}}
	req := &EnrichedRequest{RequestID: 1, Features: NewFeatureSet()}

	err := s.EnrichRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "", req.Features.Get("download_sha256_hash"))
}

func TestNewSourceRegistry(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	cfg := CampaignAgentConfig{}
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest:            {Enabled: true, Features: map[string]float64{"source_ip": 0.9}},
		constants.CampaignSourceRequestDescription: {Enabled: true, Features: map[string]float64{"ai_application": 0.5}},
		constants.CampaignSourceWhois:              {Enabled: false, Features: map[string]float64{"country": 0.3}},
	}

	reg, err := reg(cfg, fakeDB)
	require.NoError(t, err)
	assert.NotNil(t, reg)
	assert.Equal(t, 3, len(reg.sources))
	assert.Equal(t, 2, len(reg.EnabledSources()))
}

func reg(cfg CampaignAgentConfig, db database.DatabaseClient) (*SourceRegistry, error) {
	return NewSourceRegistry(cfg, db)
}

func TestNewSourceRegistry_UnknownSource(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	cfg := CampaignAgentConfig{}
	cfg.Agent.Sources = map[string]SourceConfig{
		"unknown_source": {Enabled: true, Features: map[string]float64{"foo": 1.0}},
	}

	_, err := NewSourceRegistry(cfg, fakeDB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown source")
}

func TestSourceRegistry_EnrichAll(t *testing.T) {
	registry := &SourceRegistry{
		sources: []CampaignDataSource{
			&RequestSource{enabled: true},
			&P0fSource{enabled: true, cache: map[string]cachedP0f{
				"1.2.3.4": {OsName: "Linux", OsVersion: "5.x", LinkType: "Ethernet"},
			}},
			&WhoisSource{enabled: false, cache: map[string]cachedWhois{}}, // Disabled.
		},
	}

	req := &EnrichedRequest{SourceIP: "1.2.3.4", Features: NewFeatureSet()}
	err := registry.EnrichAll(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Linux", req.Features.Get("os_name"))
}

func TestSourceRegistry_EnrichAll_CacheMissNonFatal(t *testing.T) {
	registry := &SourceRegistry{
		sources: []CampaignDataSource{
			&RequestDescriptionSource{enabled: true, cache: map[string]cachedRequestDescription{}},
		},
	}

	req := &EnrichedRequest{Features: NewFeatureSet()}
	req.Features.Set("cmp_hash", "nonexistent")
	err := registry.EnrichAll(context.Background(), req)
	require.NoError(t, err, "cache misses should be non-fatal")
	assert.Equal(t, "", req.Features.Get("ai_application"))
}

func TestSourceRegistry_PreloadAll_DBErrorNonFatal(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ErrorToReturn: errors.New("db error"),
	}

	registry := &SourceRegistry{
		sources: []CampaignDataSource{
			&RequestDescriptionSource{enabled: true, db: fakeDB},
		},
	}

	// PreloadAll should log but not panic or return errors.
	registry.PreloadAll(context.Background(), time.Time{}, time.Time{})
}
