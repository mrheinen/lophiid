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
package llm

import (
	"fmt"
	"time"
)

// Config for the LLM (primary and secondary). Used in config below and to
// initiate LLM instances.
type LLMConfig struct {
	// ApiType can be "openai" or "google"
	ApiType                   string   `fig:"api_type" default:"openai"`
	ApiLocation               string   `fig:"api_location" default:"http://localhost:8000/v1"`
	ApiKey                    string   `fig:"api_key"`
	Model                     string   `fig:"model" default:""`
	MaxContextSize            int64    `fig:"max_context_size" default:"32000"`
	Temperature               float64  `fig:"temperature" default:"0.2"`
	TopP                      float64  `fig:"top_p" default:"0.1"`
	OpenRouterProviders       []string `fig:"openrouter_providers"`
	OpenRouterReasoningEffort string   `fig:"openrouter_reasoning_effort" default:"none"`
}

// NamedLLMConfig wraps an LLMManagerConfig with a name for referencing.
type NamedLLMConfig struct {
	Name   string           `fig:"name"`
	Config LLMManagerConfig `fig:"config"`
}

// LLMManagerConfig configures the LLMManager. The CacheExpirationTime is used
// for the prompt cache which is shared between the two LLMs. A fallback
// mechanism will cause the LLMManager to switch between the primary and
// secondary LLM.
type LLMManagerConfig struct {
	PrimaryLLM          LLMConfig     `fig:"primary_llm"`
	SecondaryLLM        LLMConfig     `fig:"secondary_llm"`
	CacheExpirationTime time.Duration `fig:"cache_expiration_time" default:"24h"`
	CompletionTimeout   time.Duration `fig:"completion_timeout" default:"1m"`
	ConcurrentRequests  int           `fig:"concurrent_requests" default:"5"`
	PromptPrefix        string        `fig:"prompt_prefix" default:""`
	PromptSuffix        string        `fig:"prompt_suffix" default:""`
	FallbackInterval    time.Duration `fig:"fallback_interval" default:"1h"`
}

// FindNamedLLMConfig searches a slice of NamedLLMConfig for the given name
// and returns the matching LLMManagerConfig.
func FindNamedLLMConfig(configs []NamedLLMConfig, name string) (LLMManagerConfig, error) {
	if len(configs) == 0 {
		return LLMManagerConfig{}, fmt.Errorf("no LLM configs defined")
	}
	for _, cfg := range configs {
		if cfg.Name == name {
			return cfg.Config, nil
		}
	}
	return LLMManagerConfig{}, fmt.Errorf("LLM config %q not found", name)
}
