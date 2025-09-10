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
	ApiType               string        `fig:"api_type" default:"openai"`
	ApiLocation           string        `fig:"api_location" default:"http://localhost:8000/v1"`
	ApiKey                string        `fig:"api_key"`
	Model                 string        `fig:"model" default:""`
	MaxContextSize        int           `fig:"max_context_size" default:"32000"`
	PromptPrefix          string        `fig:"prompt_prefix" default:""`
	PromptSuffix          string        `fig:"prompt_suffix" default:""`
	LLMCompletionTimeout  time.Duration `fig:"llm_completion_timeout" default:"1m"`
	LLMConcurrentRequests int           `fig:"llm_concurrent_requests" default:"5"`
}
