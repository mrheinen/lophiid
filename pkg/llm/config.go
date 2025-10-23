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
package llm

import "time"

// Config for the LLM (primary and secondary). Used in config below and to
// initiate LLM instances.
type LLMConfig struct {
	// ApiType can be "openai" or "gemini"
	ApiType             string   `fig:"api_type" default:"openai"`
	ApiLocation         string   `fig:"api_location" default:"http://localhost:8000/v1"`
	ApiKey              string   `fig:"api_key"`
	Model               string   `fig:"model" default:""`
	MaxContextSize      int64    `fig:"max_context_size" default:"32000"`
	OpenRouterProviders []string `fig:"openrouter_providers" default:""`
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
