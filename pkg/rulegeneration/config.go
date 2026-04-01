// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package rulegeneration

// WebSearchConfig holds the configuration for the web search provider.
type WebSearchConfig struct {
	Provider   string `fig:"provider" default:"tavily"`
	APIKey     string `fig:"api_key"`
	MaxResults int    `fig:"max_results" default:"5"`
}

// AgentConfig holds all configuration for the rule generation agent.
type AgentConfig struct {
	General struct {
		LogFile  string `fig:"log_file" validate:"required"`
		LogLevel string `fig:"log_level" default:"info"`
	} `fig:"general"`
	Database struct {
		URL                string `fig:"url" validate:"required"`
		MaxOpenConnections int    `fig:"max_open_connections" default:"10"`
	} `fig:"database" validate:"required"`
	LLM struct {
		ApiType                   string  `fig:"api_type" default:"openai"`
		ApiLocation               string  `fig:"api_location" validate:"required"`
		ApiKey                    string  `fig:"api_key" validate:"required"`
		Model                     string  `fig:"model" validate:"required"`
		Temperature               float64 `fig:"temperature" default:"0.2"`
		CompletionTimeout         string  `fig:"completion_timeout" default:"10m"`
		OpenRouterReasoningEffort string  `fig:"openrouter_reasoning_effort" default:"none"`
	} `fig:"llm" validate:"required"`
	WebSearch WebSearchConfig `fig:"web_search"`
}
