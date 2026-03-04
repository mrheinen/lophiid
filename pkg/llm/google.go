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
	"encoding/json"
	"fmt"
	"log/slog"
	"lophiid/pkg/util/constants"
	"time"

	"github.com/invopop/jsonschema"
	"google.golang.org/genai"
)

// GoogleLLMClient is an LLM client that uses the Google Gemini API via
// google.golang.org/genai.
type GoogleLLMClient struct {
	client         *genai.Client
	model          string
	systemPrompt   string
	maxContextSize int64
	temperature    float64
	topP           float64
	debugEnabled   bool
	schema         map[string]any
}

// NewGoogleLLMClient creates a new GoogleLLMClient using the Gemini API backend.
func NewGoogleLLMClient(cfg LLMConfig, systemPrompt string) *GoogleLLMClient {
	if cfg.Model == "" {
		slog.Error("model is required for GoogleLLMClient")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  cfg.ApiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		slog.Error("error creating Google genai client", slog.String("error", err.Error()))
		return nil
	}

	return &GoogleLLMClient{
		client:         client,
		model:          cfg.Model,
		systemPrompt:   systemPrompt,
		maxContextSize: cfg.MaxContextSize,
		temperature:    cfg.Temperature,
		topP:           cfg.TopP,
	}
}

// LoadedModel returns the model name used by this client.
func (g *GoogleLLMClient) LoadedModel() string {
	return g.model
}

// EnableDebug enables or disables debug logging for API calls.
func (g *GoogleLLMClient) EnableDebug(enabled bool) {
	g.debugEnabled = enabled
}

// SetResponseSchemaFromObject reflects the given object into a JSON schema and
// stores it for use in subsequent GenerateContent calls as a structured output
// constraint. When a schema is set, responses will be JSON conforming to it.
func (g *GoogleLLMClient) SetResponseSchemaFromObject(obj any, title string) error {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}

	schema := reflector.Reflect(obj)
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("error marshaling JSON schema: %w", err)
	}

	var schemaMap map[string]any
	if err := json.Unmarshal(schemaBytes, &schemaMap); err != nil {
		return fmt.Errorf("error unmarshaling JSON schema: %w", err)
	}

	g.schema = schemaMap
	return nil
}

// Complete sends a single prompt to the Gemini API and returns the response.
func (g *GoogleLLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	truncatedPrompt := truncatePrompt(prompt, g.maxContextSize)

	msgs := []LLMMessage{}
	if g.systemPrompt != "" {
		msgs = append(msgs, LLMMessage{
			Role:    constants.LLMClientMessageSystem,
			Content: g.systemPrompt,
		})
	}

	msgs = append(msgs, LLMMessage{
		Role:    constants.LLMClientMessageUser,
		Content: truncatedPrompt,
	})

	return g.CompleteWithMessages(ctx, msgs)
}

// CompleteWithMessages sends a sequence of messages to the Gemini API and
// returns the response. The last message must have the user role.
func (g *GoogleLLMClient) CompleteWithMessages(ctx context.Context, msgs []LLMMessage) (string, error) {
	if len(msgs) == 0 {
		return "", fmt.Errorf("messages must not be empty")
	}

	lastMessage := &msgs[len(msgs)-1]
	if lastMessage.Role != constants.LLMClientMessageUser {
		return "", fmt.Errorf("last message must be user")
	}

	config := &genai.GenerateContentConfig{}

	if g.temperature >= 0 {
		temp := float32(g.temperature)
		config.Temperature = &temp
	}
	if g.topP >= 0 {
		topP := float32(g.topP)
		config.TopP = &topP
	}

	if g.schema != nil {
		config.ResponseMIMEType = "application/json"
		config.ResponseJsonSchema = g.schema
	}

	// If a struct-level system prompt is set and no message overrides it, apply it.
	if g.systemPrompt != "" {
		config.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{{Text: g.systemPrompt}},
		}
	}

	var contents []*genai.Content
	for i := range msgs {
		switch msgs[i].Role {
		case constants.LLMClientMessageSystem:
			// System messages override the struct-level systemPrompt.
			config.SystemInstruction = &genai.Content{
				Parts: []*genai.Part{{Text: msgs[i].Content}},
			}
		case constants.LLMClientMessageUser:
			contents = append(contents, &genai.Content{
				Role:  "user",
				Parts: []*genai.Part{{Text: msgs[i].Content}},
			})
		case constants.LLMClientMessageAssistant, constants.LLMClientMessageModel:
			contents = append(contents, &genai.Content{
				Role:  "model",
				Parts: []*genai.Part{{Text: msgs[i].Content}},
			})
		default:
			return "", fmt.Errorf("unknown role: %s", msgs[i].Role)
		}
	}

	if g.debugEnabled {
		slog.Debug("GoogleLLMClient request",
			slog.String("model", g.model),
			slog.Int("message_count", len(contents)),
			slog.Bool("schema_set", g.schema != nil))
	}

	result, err := g.client.Models.GenerateContent(ctx, g.model, contents, config)
	if err != nil {
		return "", fmt.Errorf("GenerateContent error: %w", err)
	}

	text := result.Text()
	if text == "" {
		return "", fmt.Errorf("GenerateContent returned empty response")
	}

	return text, nil
}

// CompleteWithTools is not yet implemented for GoogleLLMClient.
func (g *GoogleLLMClient) CompleteWithTools(ctx context.Context, msgs []LLMMessage, tools []LLMTool) (string, error) {
	return "", fmt.Errorf("CompleteWithTools not yet implemented for GoogleLLMClient")
}
