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

import (
	"log/slog"
	"lophiid/pkg/util"
)

// GetLLMManager returns the LLM manager configured in the config
func GetLLMManager(cfg LLMManagerConfig, llmMetrics *LLMMetrics) LLMManagerInterface {
	pCache := util.NewStringMapCache[string]("LLM prompt cache", cfg.CacheExpirationTime)
	primaryLLMClient := NewLLMClient(cfg.PrimaryLLM, "")
	primaryManager := NewLLMManager(primaryLLMClient, pCache, llmMetrics, cfg.CompletionTimeout, cfg.ConcurrentRequests, true, cfg.PromptPrefix, cfg.PromptSuffix)

	// Check if secondary LLM is configured (non-empty API key indicates configuration)
	if cfg.SecondaryLLM.ApiKey == "" {
		slog.Info("Using single LLM manager")
		return primaryManager
	}

	slog.Info("Secondary LLM configured, using DualLLMManager")
	secondaryLLMClient := NewLLMClient(cfg.SecondaryLLM, "")
	secondaryManager := NewLLMManager(secondaryLLMClient, pCache, llmMetrics, cfg.CompletionTimeout, cfg.ConcurrentRequests, true, cfg.PromptPrefix, cfg.PromptSuffix)

	return NewDualLLMManager(primaryManager, secondaryManager, cfg.FallbackInterval)
}
