// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
	"context"
	"log/slog"
)

type LLMClient interface {
	Complete(ctx context.Context, prompt string) (string, error)
	LoadedModel() string
}

type MockLLMClient struct {
	CompletionToReturn string
	LastReceivedPrompt string
	ErrorToReturn      error
}

func (m *MockLLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	m.LastReceivedPrompt = prompt
	return m.CompletionToReturn, m.ErrorToReturn
}

func (m *MockLLMClient) LoadedModel() string {
	return "gpt-3.5-turbo"
}

func NewLLMClient(cfg LLMConfig) LLMClient {
	// OpenAI
	switch cfg.ApiType {
	case "openai":
		if cfg.Model == "" {
			// TODO: rething the prompt template argument.
			return NewOpenAILLMClient(cfg.ApiKey, cfg.ApiLocation, "%s", cfg.MaxContextSize)
		} else {
			return NewOpenAILLMClientWithModel(cfg.ApiKey, cfg.ApiLocation, "%s", cfg.Model, cfg.MaxContextSize)
		}
	case "gemini":
		return NewGeminiLLMMClient(cfg.ApiKey, "%s", cfg.Model, cfg.MaxContextSize, cfg.GeminiThinkingBudget)
	default:
		slog.Error("unknown LLM type", slog.String("type", cfg.ApiType))
		return nil
	}
}

// truncatePrompt truncates the prompt if it exceeds the maximum context size
func truncatePrompt(prompt string, maxContextSize int64) string {
	if maxContextSize <= 0 || len(prompt) <= int(maxContextSize) {
		return prompt
	}

	return prompt[:maxContextSize]
}
