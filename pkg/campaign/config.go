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
	"fmt"
	"time"

	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
)

// ValidSourceNames is the set of recognized data source names.
var ValidSourceNames = map[string]bool{
	constants.CampaignSourceRequest:            true,
	constants.CampaignSourceRequestDescription: true,
	constants.CampaignSourceWhois:              true,
	constants.CampaignSourceP0f:                true,
	constants.CampaignSourceIpEvent:            true,
	constants.CampaignSourceSession:            true,
	constants.CampaignSourceDownloads:          true,
}

// ValidCorrelationFeatures is the set of recognized correlation features.
var ValidCorrelationFeatures = map[string]bool{
	constants.CampaignCorrelationSessionID: true,
	constants.CampaignCorrelationSourceIP:  true,
	constants.CampaignCorrelationSubnet:    true,
}

// FeatureConfig configures a single feature within a data source.
type FeatureConfig struct {
	// Weight is the similarity score contribution when this feature matches.
	Weight float64 `fig:"weight"`
	// ExhaustNumber is the maximum number of distinct values this feature may
	// accumulate in a campaign fingerprint before it is ignored for matching.
	// 0 means the feature is never exhausted.
	ExhaustNumber int `fig:"exhaust_number"`
}

// SourceConfig configures a single data source for the campaign agent.
type SourceConfig struct {
	Enabled  bool                     `fig:"enabled"`
	Features map[string]FeatureConfig `fig:"features"`
	Options  map[string]string        `fig:"options"`
}

// LLMPromptsConfig holds configurable LLM prompt templates.
type LLMPromptsConfig struct {
	SummarizeTemplate string `fig:"summarize_template" default:""`
	FinalTemplate     string `fig:"final_template" default:""`
}

// CampaignAgentConfig holds all configuration for the campaign clustering agent.
type CampaignAgentConfig struct {
	General struct {
		LogFile  string `fig:"log_file" validate:"required"`
		LogLevel string `fig:"log_level" default:"debug"`
	} `fig:"general"`
	Database struct {
		URL                string `fig:"url" validate:"required"`
		MaxOpenConnections int    `fig:"max_open_connections" default:"10"`
	} `fig:"database" validate:"required"`
	Metrics struct {
		ListenAddress string `fig:"listen_address" default:"localhost:8996"`
	} `fig:"prometheus"`
	LLM struct {
		LLMConfig string `fig:"llm_config"`
		// LLMConfigs holds named LLM configurations that can be referenced.
		LLMConfigs []llm.NamedLLMConfig `fig:"llm_configs"`
	} `fig:"llm"`
	Agent struct {
		// ScanInterval is how often the pipeline runs in interval mode.
		ScanInterval time.Duration `fig:"scan_interval" default:"1h"`
		// LookbackWindow is the time window of requests to consider per pipeline run.
		LookbackWindow time.Duration `fig:"lookback_window" default:"24h"`
		// CampaignMinRequests is the minimum number of requests for a cluster to qualify as a campaign.
		CampaignMinRequests int `fig:"campaign_min_requests" default:"50"`
		// CampaignMinSourceIPs is the minimum number of unique source IPs for a cluster to qualify as a campaign.
		CampaignMinSourceIPs int `fig:"campaign_min_source_ips" default:"10"`
		// SimilarityThreshold is the minimum weighted similarity score to match a request to a campaign or merge two campaigns.
		SimilarityThreshold float64 `fig:"similarity_threshold" default:"1.0"`
		// ActiveWindow is how long after last_seen_at an ACTIVE campaign waits before transitioning to DORMANT.
		ActiveWindow time.Duration `fig:"active_window" default:"48h"`
		// CloseWindow is how long after last_seen_at a DORMANT campaign waits before transitioning to CLOSED.
		CloseWindow time.Duration `fig:"close_window" default:"168h"`
		// ResummarizeThreshold is the fractional growth in request count that triggers LLM re-summarization.
		ResummarizeThreshold float64 `fig:"resummarize_threshold" default:"0.2"`
		// RetroactiveLookback is how far back to search for historical matches when a new campaign is created.
		RetroactiveLookback time.Duration `fig:"retroactive_lookback" default:"168h"`
		// CorrelationPadding is the time buffer added before first_seen and after last_seen when querying correlated requests.
		CorrelationPadding time.Duration `fig:"correlation_padding" default:"1h"`
		// CorrelationFeatures lists which correlators to use (e.g. subnet).
		CorrelationFeatures []string `fig:"correlation_features"`
		// Sources maps source names to their configuration (enabled flag and per-feature weights).
		Sources map[string]SourceConfig `fig:"sources"`
		// LLMPrompts holds configurable LLM prompt templates for campaign summarization.
		LLMPrompts LLMPromptsConfig `fig:"llm_prompts"`
	} `fig:"campaign_agent" validate:"required"`
}

// GetLLMConfig returns the LLM configuration for the given name.
func (c *CampaignAgentConfig) GetLLMConfig(name string) (llm.LLMManagerConfig, error) {
	return llm.FindNamedLLMConfig(c.LLM.LLMConfigs, name)
}

// Validate checks the configuration for logical errors and invalid values.
func (c *CampaignAgentConfig) Validate() error {
	if c.Agent.ScanInterval <= 0 {
		return fmt.Errorf("scan_interval must be positive")
	}
	if c.Agent.LookbackWindow <= 0 {
		return fmt.Errorf("lookback_window must be positive")
	}
	if c.Agent.CampaignMinRequests <= 0 && c.Agent.CampaignMinSourceIPs <= 0 {
		return fmt.Errorf("at least one of campaign_min_requests or campaign_min_source_ips must be positive")
	}
	if c.Agent.SimilarityThreshold <= 0 {
		return fmt.Errorf("similarity_threshold must be positive")
	}
	if c.Agent.ActiveWindow <= 0 {
		return fmt.Errorf("active_window must be positive")
	}
	if c.Agent.CloseWindow <= 0 {
		return fmt.Errorf("close_window must be positive")
	}
	if c.Agent.CloseWindow < c.Agent.ActiveWindow {
		return fmt.Errorf("close_window (%s) must be >= active_window (%s)", c.Agent.CloseWindow, c.Agent.ActiveWindow)
	}
	if c.Agent.ResummarizeThreshold < 0 || c.Agent.ResummarizeThreshold > 1 {
		return fmt.Errorf("resummarize_threshold must be between 0 and 1, got %f", c.Agent.ResummarizeThreshold)
	}
	if c.Agent.RetroactiveLookback < 0 {
		return fmt.Errorf("retroactive_lookback must be non-negative")
	}
	if c.Agent.CorrelationPadding < 0 {
		return fmt.Errorf("correlation_padding must be non-negative")
	}

	// Validate correlation features.
	for _, f := range c.Agent.CorrelationFeatures {
		if !ValidCorrelationFeatures[f] {
			return fmt.Errorf("unknown correlation feature %q; valid features: %v", f, validCorrelationFeatureNames())
		}
	}

	// Validate sources.
	hasEnabledSource := false
	for name, src := range c.Agent.Sources {
		if !ValidSourceNames[name] {
			return fmt.Errorf("unknown source %q; valid sources: %v", name, validSourceNames())
		}
		if src.Enabled {
			hasEnabledSource = true
			if len(src.Features) == 0 {
				return fmt.Errorf("source %q is enabled but has no features defined", name)
			}
			for featureName, fc := range src.Features {
				if fc.Weight < 0 {
					return fmt.Errorf("source %q feature %q has negative weight %f", name, featureName, fc.Weight)
				}
				if fc.ExhaustNumber < 0 {
					return fmt.Errorf("source %q feature %q has negative exhaust_number %d", name, featureName, fc.ExhaustNumber)
				}
			}
		}
	}
	if !hasEnabledSource {
		return fmt.Errorf("at least one source must be enabled")
	}

	return nil
}

// validSourceNames returns sorted source names for error messages.
func validSourceNames() []string {
	names := make([]string, 0, len(ValidSourceNames))
	for n := range ValidSourceNames {
		names = append(names, n)
	}
	return names
}

// validCorrelationFeatureNames returns sorted correlation feature names for error messages.
func validCorrelationFeatureNames() []string {
	names := make([]string, 0, len(ValidCorrelationFeatures))
	for n := range ValidCorrelationFeatures {
		names = append(names, n)
	}
	return names
}
