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
	"testing"
	"time"

	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validTestConfig returns a minimal valid CampaignAgentConfig for testing.
func validTestConfig() CampaignAgentConfig {
	cfg := CampaignAgentConfig{}
	cfg.General.LogFile = "/tmp/test.log"
	cfg.General.LogLevel = "debug"
	cfg.Database.URL = "postgres://localhost/test"
	cfg.Agent.ScanInterval = 1 * time.Hour
	cfg.Agent.LookbackWindow = 24 * time.Hour
	cfg.Agent.CampaignMinRequests = 50
	cfg.Agent.CampaignMinSourceIPs = 10
	cfg.Agent.SimilarityThreshold = 1.0
	cfg.Agent.ActiveWindow = 48 * time.Hour
	cfg.Agent.CloseWindow = 168 * time.Hour
	cfg.Agent.ResummarizeThreshold = 0.2
	cfg.Agent.RetroactiveLookback = 168 * time.Hour
	cfg.Agent.CorrelationPadding = 1 * time.Hour
	cfg.Agent.CorrelationFeatures = []string{constants.CampaignCorrelationSessionID, constants.CampaignCorrelationSourceIP}
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {
			Enabled: true,
			Features: map[string]float64{
				"source_ip": 0.9,
				"cmp_hash":  0.8,
			},
		},
	}
	return cfg
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validTestConfig()
	assert.NoError(t, cfg.Validate())
}

func TestValidate_ZeroScanInterval(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.ScanInterval = 0
	assert.ErrorContains(t, cfg.Validate(), "scan_interval must be positive")
}

func TestValidate_ZeroLookbackWindow(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.LookbackWindow = 0
	assert.ErrorContains(t, cfg.Validate(), "lookback_window must be positive")
}

func TestValidate_ZeroCampaignThresholds(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CampaignMinRequests = 0
	cfg.Agent.CampaignMinSourceIPs = 0
	assert.ErrorContains(t, cfg.Validate(), "at least one of campaign_min_requests or campaign_min_source_ips must be positive")
}

func TestValidate_OnlyMinRequestsPositive(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CampaignMinRequests = 50
	cfg.Agent.CampaignMinSourceIPs = 0
	assert.NoError(t, cfg.Validate())
}

func TestValidate_OnlyMinSourceIPsPositive(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CampaignMinRequests = 0
	cfg.Agent.CampaignMinSourceIPs = 10
	assert.NoError(t, cfg.Validate())
}

func TestValidate_ZeroSimilarityThreshold(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.SimilarityThreshold = 0
	assert.ErrorContains(t, cfg.Validate(), "similarity_threshold must be positive")
}

func TestValidate_ZeroActiveWindow(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.ActiveWindow = 0
	assert.ErrorContains(t, cfg.Validate(), "active_window must be positive")
}

func TestValidate_ZeroCloseWindow(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CloseWindow = 0
	assert.ErrorContains(t, cfg.Validate(), "close_window must be positive")
}

func TestValidate_CloseWindowLessThanActiveWindow(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.ActiveWindow = 48 * time.Hour
	cfg.Agent.CloseWindow = 24 * time.Hour
	assert.ErrorContains(t, cfg.Validate(), "close_window")
}

func TestValidate_ResummarizeThresholdOutOfRange(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.ResummarizeThreshold = 1.5
	assert.ErrorContains(t, cfg.Validate(), "resummarize_threshold must be between 0 and 1")

	cfg.Agent.ResummarizeThreshold = -0.1
	assert.ErrorContains(t, cfg.Validate(), "resummarize_threshold must be between 0 and 1")
}

func TestValidate_NegativeRetroactiveLookback(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.RetroactiveLookback = -1 * time.Hour
	assert.ErrorContains(t, cfg.Validate(), "retroactive_lookback must be non-negative")
}

func TestValidate_NegativeCorrelationPadding(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CorrelationPadding = -1 * time.Hour
	assert.ErrorContains(t, cfg.Validate(), "correlation_padding must be non-negative")
}

func TestValidate_UnknownCorrelationFeature(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CorrelationFeatures = []string{constants.CampaignCorrelationSessionID, "bogus"}
	assert.ErrorContains(t, cfg.Validate(), "unknown correlation feature \"bogus\"")
}

func TestValidate_ValidCorrelationFeatures(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.CorrelationFeatures = []string{constants.CampaignCorrelationSessionID, constants.CampaignCorrelationSourceIP, constants.CampaignCorrelationSubnet}
	assert.NoError(t, cfg.Validate())
}

func TestValidate_UnknownSourceName(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Sources["nonexistent"] = SourceConfig{Enabled: true, Features: map[string]float64{"foo": 0.5}}
	assert.ErrorContains(t, cfg.Validate(), "unknown source \"nonexistent\"")
}

func TestValidate_NoEnabledSources(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {Enabled: false},
	}
	assert.ErrorContains(t, cfg.Validate(), "at least one source must be enabled")
}

func TestValidate_EnabledSourceNoFeatures(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {Enabled: true, Features: map[string]float64{}},
	}
	assert.ErrorContains(t, cfg.Validate(), "source \"request\" is enabled but has no features defined")
}

func TestValidate_NegativeFeatureWeight(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {Enabled: true, Features: map[string]float64{"source_ip": -0.5}},
	}
	assert.ErrorContains(t, cfg.Validate(), "negative weight")
}

func TestValidate_MultipleValidSources(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Sources = map[string]SourceConfig{
		constants.CampaignSourceRequest: {Enabled: true, Features: map[string]float64{"source_ip": 0.9}},
		constants.CampaignSourceWhois:   {Enabled: true, Features: map[string]float64{"geoip_asn": 0.3}},
		constants.CampaignSourceP0f:     {Enabled: false},
	}
	assert.NoError(t, cfg.Validate())
}

func TestGetLLMConfig_Found(t *testing.T) {
	cfg := validTestConfig()
	cfg.LLM.LLMConfigs = []llm.NamedLLMConfig{
		{
			Name:   "test-llm",
			Config: llm.LLMManagerConfig{ConcurrentRequests: 5},
		},
	}
	result, err := cfg.GetLLMConfig("test-llm")
	require.NoError(t, err)
	assert.Equal(t, 5, result.ConcurrentRequests)
}

func TestGetLLMConfig_NotFound(t *testing.T) {
	cfg := validTestConfig()
	cfg.LLM.LLMConfigs = []llm.NamedLLMConfig{
		{Name: "other"},
	}
	_, err := cfg.GetLLMConfig("missing")
	assert.ErrorContains(t, err, "LLM config \"missing\" not found")
}

func TestGetLLMConfig_NoConfigs(t *testing.T) {
	cfg := validTestConfig()
	cfg.LLM.LLMConfigs = nil
	_, err := cfg.GetLLMConfig("any")
	assert.ErrorContains(t, err, "no LLM configs defined")
}
