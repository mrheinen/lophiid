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

// buildBaseConfig creates a GenerateContentConfig populated with temperature,
// topP, and the struct-level system prompt.
func (g *GoogleLLMClient) buildBaseConfig() *genai.GenerateContentConfig {
	config := &genai.GenerateContentConfig{}
	if g.temperature >= 0 {
		temp := float32(g.temperature)
		config.Temperature = &temp
	}
	if g.topP >= 0 {
		topP := float32(g.topP)
		config.TopP = &topP
	}
	if g.systemPrompt != "" {
		config.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{{Text: g.systemPrompt}},
		}
	}
	return config
}

// buildContents converts []LLMMessage to a slice of genai.Content for the
// conversation turns. Any system message in msgs overrides the system
// instruction already set on config.
func (g *GoogleLLMClient) buildContents(msgs []LLMMessage, config *genai.GenerateContentConfig) ([]*genai.Content, error) {
	var contents []*genai.Content
	for i := range msgs {
		switch msgs[i].Role {
		case constants.LLMClientMessageSystem:
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
			return nil, fmt.Errorf("unknown role: %s", msgs[i].Role)
		}
	}
	return contents, nil
}

// dispatchFunctionCall marshals the function call arguments, invokes the
// matching tool via findAndCallTool, logs the outcome, and returns a
// genai.Part carrying the FunctionResponse to send back to the model.
func (g *GoogleLLMClient) dispatchFunctionCall(fc *genai.FunctionCall, tools []LLMTool) *genai.Part {
	argsJSON, err := json.Marshal(fc.Args)
	if err != nil {
		slog.Error("error marshaling tool args",
			slog.String("tool", fc.Name),
			slog.String("error", err.Error()))
		argsJSON = []byte("{}")
	}

	slog.Debug("GoogleLLMClient executing tool",
		slog.String("tool", fc.Name),
		slog.String("args", string(argsJSON)))

	toolResult, err := findAndCallTool(fc.Name, string(argsJSON), tools)
	if err != nil {
		slog.Error("tool call failed",
			slog.String("tool", fc.Name),
			slog.String("error", err.Error()))
		toolResult = "could not run tool successfully"
	}

	slog.Debug("GoogleLLMClient tool result",
		slog.String("tool", fc.Name),
		slog.String("result", toolResult))

	return &genai.Part{
		FunctionResponse: &genai.FunctionResponse{
			Name:     fc.Name,
			Response: map[string]any{"output": toolResult},
		},
	}
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
	if msgs[len(msgs)-1].Role != constants.LLMClientMessageUser {
		return "", fmt.Errorf("last message must be user")
	}

	config := g.buildBaseConfig()
	if g.schema != nil {
		config.ResponseMIMEType = "application/json"
		config.ResponseJsonSchema = g.schema
	}

	contents, err := g.buildContents(msgs, config)
	if err != nil {
		return "", err
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

// CompleteWithTools sends a sequence of messages to the Gemini API with function
// calling support. It runs a loop (up to maxToolIterations) dispatching tool calls
// made by the model until the model produces a plain-text final response.
func (g *GoogleLLMClient) CompleteWithTools(ctx context.Context, msgs []LLMMessage, tools []LLMTool, maxToolIterations int) (string, error) {
	if len(msgs) == 0 {
		return "", fmt.Errorf("messages must not be empty")
	}
	if msgs[len(msgs)-1].Role != constants.LLMClientMessageUser {
		return "", fmt.Errorf("last message must be user")
	}
	if len(tools) == 0 {
		return "", fmt.Errorf("CompleteWithTools requires at least one tool")
	}

	config := g.buildBaseConfig()
	contents, err := g.buildContents(msgs, config)
	if err != nil {
		return "", err
	}

	// Build FunctionDeclarations from the provided tools.
	// Schema (if set) is deferred until after all tool calls complete so that
	// it is never active at the same time as the tool declarations.
	var decls []*genai.FunctionDeclaration
	for _, t := range tools {
		decls = append(decls, &genai.FunctionDeclaration{
			Name:                 t.Name,
			Description:          t.Description,
			ParametersJsonSchema: t.Parameters,
		})
	}
	config.Tools = []*genai.Tool{{FunctionDeclarations: decls}}

	for iteration := range maxToolIterations {
		slog.Debug("GoogleLLMClient tool calling iteration",
			slog.String("model", g.model),
			slog.Int("iteration", iteration),
			slog.Int("message_count", len(contents)))

		result, err := g.client.Models.GenerateContent(ctx, g.model, contents, config)
		if err != nil {
			return "", fmt.Errorf("GenerateContent error: %w", err)
		}
		if len(result.Candidates) == 0 {
			return "", fmt.Errorf("GenerateContent returned no candidates")
		}

		modelContent := result.Candidates[0].Content

		// Collect all function calls from the model's response parts.
		var funcCalls []*genai.FunctionCall
		for _, part := range modelContent.Parts {
			if part.FunctionCall != nil {
				funcCalls = append(funcCalls, part.FunctionCall)
			}
		}

		if len(funcCalls) > 0 {
			slog.Debug("GoogleLLMClient processing tool calls", slog.Int("count", len(funcCalls)))
			contents = append(contents, modelContent)

			var responseParts []*genai.Part
			for _, fc := range funcCalls {
				responseParts = append(responseParts, g.dispatchFunctionCall(fc, tools))
			}

			// Append the tool results as a user turn.
			contents = append(contents, &genai.Content{
				Role:  "user",
				Parts: responseParts,
			})
			continue
		}

		// No function calls in this iteration.
		// If tools were still active and a schema is required, drop tools and
		// apply the schema so the model produces structured output.
		// Effectively this is like saying: "Here's what you just wrote — now reformat it as JSON matching this schema."
		if config.Tools != nil && g.schema != nil {
			slog.Debug("GoogleLLMClient no tools called but schema required, applying schema")
			contents = append(contents, modelContent)
			config.Tools = nil
			config.ResponseMIMEType = "application/json"
			config.ResponseJsonSchema = g.schema
			continue
		}

		text := result.Text()
		if text == "" {
			return "", fmt.Errorf("GenerateContent returned empty response")
		}
		return text, nil
	}

	return "", fmt.Errorf("exceeded maximum tool call iterations")
}
