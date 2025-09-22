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
	"context"
	"log/slog"

	"github.com/invopop/jsonschema"
)

type LLMClient interface {
	Complete(ctx context.Context, prompt string) (string, error)
	CompleteWithMessages(ctx context.Context, msgs []LLMMessage) (string, error)
	SetResponseSchemaFromObject(obj any, title string)
	LoadedModel() string
}

type LLMMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
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

func (m *MockLLMClient) CompleteWithMessages(ctx context.Context, msgs []LLMMessage) (string, error) {
	return m.CompletionToReturn, m.ErrorToReturn
}

func (m *MockLLMClient) LoadedModel() string {
	return "gpt-3.5-turbo"
}

func (m *MockLLMClient) SetResponseSchemaFromObject(obj any) {
}

// GenerateSchema generates a schema for the OpenAI API. Useful for structured
// output.
func GenerateSchema[T any]() any {
	// Structured Outputs uses a subset of JSON schema
	// These flags are necessary to comply with the subset
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}
	var v T
	return reflector.Reflect(v)
}

func NewLLMClient(cfg LLMConfig, systemPrompt string) LLMClient {
	// OpenAI
	switch cfg.ApiType {
	case "openai":
		if cfg.Model == "" {
			return NewOpenAILLMClient(cfg.ApiKey, cfg.ApiLocation, systemPrompt, cfg.MaxContextSize)
		} else {
			return NewOpenAILLMClientWithModel(cfg.ApiKey, cfg.ApiLocation, systemPrompt, cfg.Model, cfg.MaxContextSize)
		}
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
