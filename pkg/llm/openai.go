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
	"fmt"
	"log/slog"
	"lophiid/pkg/util/constants"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
)

type OpenAILLMClient struct {
	client *openai.Client
	Model  string
	// systemPrompt is used to construct the prompt. It needs to contain a
	// single %s at a location where the request prompt needs to go.
	systemPrompt string
	// maxContextSize is the maximum number of characters allowed in the context
	maxContextSize int64
	temperature    float64
	top_p          float64
	schema         *openai.ResponseFormatJSONSchemaJSONSchemaParam
	providers      []string
	debugEnabled   bool
}

// NewOpenAILLMClientWithModel creates a new OpenAILLMClient with the given
// model and maximum context size.
func NewOpenAILLMClientWithModel(cfg LLMConfig, systemPrompt string) *OpenAILLMClient {
	client := openai.NewClient(
		option.WithAPIKey(cfg.ApiKey),
		option.WithBaseURL(cfg.ApiLocation),
	)

	ret := &OpenAILLMClient{
		client:         &client,
		systemPrompt:   systemPrompt,
		Model:          cfg.Model,
		maxContextSize: cfg.MaxContextSize,
		providers:      cfg.OpenRouterProviders,
		temperature:    cfg.Temperature,
		top_p:          cfg.TopP,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	models, err := client.Models.List(ctx)
	if err != nil {
		slog.Error("error listing models", slog.String("error", err.Error()))
		return nil
	}

	for _, m := range models.Data {
		if m.ID == cfg.Model {
			return ret
		}
	}

	slog.Error("could not find model", slog.String("model", cfg.Model), slog.String("models", fmt.Sprintf("%+v", models.Data)))
	return nil
}

// NewOpenAILLMClient creates a new OpenAILLMClient and auto selects a model
// from the API. Use this when talking with an API that only has one model.
func NewOpenAILLMClient(cfg LLMConfig, promptTemplate string) *OpenAILLMClient {

	client := openai.NewClient(
		option.WithAPIKey(cfg.ApiKey),
		option.WithBaseURL(cfg.ApiLocation),
	)

	ret := &OpenAILLMClient{
		client:         &client,
		systemPrompt:   promptTemplate,
		maxContextSize: cfg.MaxContextSize,
		schema:         nil,
		providers:      cfg.OpenRouterProviders,
		temperature:    cfg.Temperature,
		top_p:          cfg.TopP,
	}

	if err := ret.SelectModel(); err != nil {
		slog.Error("Error finding model", slog.String("error", err.Error()))
		return nil
	}

	slog.Info("Selected model", slog.String("model", ret.Model))
	return ret
}

func (l *OpenAILLMClient) LoadedModel() string {
	return l.Model
}

// EnableDebug enables or disables debug logging for OpenAI API calls
func (l *OpenAILLMClient) EnableDebug(enabled bool) {
	l.debugEnabled = enabled
}

func (l *OpenAILLMClient) SetResponseSchemaFromObject(obj any, title string) {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}

	schema := reflector.Reflect(obj)
	l.schema = &openai.ResponseFormatJSONSchemaJSONSchemaParam{
		Name:        "response_schema",
		Description: openai.String(title),
		Schema:      schema,
		Strict:      openai.Bool(true),
	}
}

// SelectModel queries the OpenAI API for models and selects the first model.
func (l *OpenAILLMClient) SelectModel() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	models, err := l.client.Models.List(ctx)
	defer cancel()
	if err != nil {
		return fmt.Errorf("error listing models: %w", err)
	}

	if len(models.Data) == 0 {
		return fmt.Errorf("no models found")
	}

	slog.Info("using the model", slog.String("model", models.Data[0].ID))

	l.Model = models.Data[0].ID
	return nil
}

// Complete complete a single LLM prompt
func (l *OpenAILLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	truncatedPrompt := truncatePrompt(prompt, int64(l.maxContextSize))

	msgs := []LLMMessage{}

	if l.systemPrompt != "" {
		msgs = append(msgs, LLMMessage{
			Role:    constants.LLMClientMessageSystem,
			Content: l.systemPrompt,
		})
	}

	msgs = append(msgs, LLMMessage{
		Role:    constants.LLMClientMessageUser,
		Content: truncatedPrompt,
	})

	return l.CompleteWithMessages(ctx, msgs)
}

// CompleteWithMessages complete a sequence of LLM messages. The last message
// needs to be a user message.
func (l *OpenAILLMClient) CompleteWithMessages(ctx context.Context, msgs []LLMMessage) (string, error) {
	lastMessage := &msgs[len(msgs)-1]
	if lastMessage.Role != constants.LLMClientMessageUser {
		return "", fmt.Errorf("last message must be user")
	}

	param := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{},
		Model:    l.Model,
	}

	if l.temperature >= 0 {
		param.Temperature = openai.Float(l.temperature)
	}
	if l.top_p >= 0 {
		param.TopP = openai.Float(l.top_p)
	}

	if l.systemPrompt != "" && msgs[0].Role != constants.LLMClientMessageSystem {
		param.Messages = append(param.Messages, openai.SystemMessage(l.systemPrompt))
	}

	for i := range msgs {
		switch msgs[i].Role {
		case constants.LLMClientMessageUser:
			param.Messages = append(param.Messages, openai.UserMessage(msgs[i].Content))
		case constants.LLMClientMessageAssistant:
			param.Messages = append(param.Messages, openai.AssistantMessage(msgs[i].Content))
		case constants.LLMClientMessageSystem:
			for i := range param.Messages {
				if *param.Messages[i].GetRole() == constants.LLMClientMessageSystem {
					return "", fmt.Errorf("duplicate system message")
				}
			}
			param.Messages = append(param.Messages, openai.SystemMessage(msgs[i].Content))

		default:
			return "", fmt.Errorf("unknown role: %s", msgs[i].Role)
		}
	}

	if l.schema != nil {
		slog.Debug("setting response schema")
		param.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{
				JSONSchema: *l.schema,
			},
		}
	}

	var opts []option.RequestOption
	if l.debugEnabled {
		opts = append(opts, option.WithDebugLog(nil))
	}

	if len(l.providers) > 0 {
		opts = append(opts, option.WithJSONSet("provider", map[string]any{
			"require_parameters": true,
			"order":              l.providers,
			"allow_fallbacks":    true,
		}))
	}

//	if l.top_k > 0 {
//		opts = append(opts, option.WithJSONSet("top_k", l.top_k))
//	}

	resp, err := l.client.Chat.Completions.New(ctx, param, opts...)

	if err != nil {
		return "", fmt.Errorf("chat completion error: %v", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("chat returned nothing")
	}

	return resp.Choices[0].Message.Content, nil
}

// CompleteWithTools completes a sequence of LLM messages with tool support.
func (l *OpenAILLMClient) CompleteWithTools(ctx context.Context, msgs []LLMMessage, tools []LLMTool) (string, error) {
	lastMessage := &msgs[len(msgs)-1]
	if lastMessage.Role != constants.LLMClientMessageUser {
		return "", fmt.Errorf("last message must be user")
	}

	param := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{},
		Model:    l.Model,
	}

	if l.temperature >= 0 {
		param.Temperature = openai.Float(l.temperature)
	}
	if l.top_p >= 0 {
		param.TopP = openai.Float(l.top_p)
	}

	if l.systemPrompt != "" && msgs[0].Role != constants.LLMClientMessageSystem {
		param.Messages = append(param.Messages, openai.SystemMessage(l.systemPrompt))
	}

	for i := range msgs {
		switch msgs[i].Role {
		case constants.LLMClientMessageUser:
			param.Messages = append(param.Messages, openai.UserMessage(msgs[i].Content))
		case constants.LLMClientMessageAssistant:
			param.Messages = append(param.Messages, openai.AssistantMessage(msgs[i].Content))
		case constants.LLMClientMessageSystem:
			for i := range param.Messages {
				if *param.Messages[i].GetRole() == constants.LLMClientMessageSystem {
					return "", fmt.Errorf("duplicate system message")
				}
			}
			param.Messages = append(param.Messages, openai.SystemMessage(msgs[i].Content))
		default:
			return "", fmt.Errorf("unknown role: %s", msgs[i].Role)
		}
	}

	// Add tools to the parameters
	if len(tools) > 0 {
		openaiTools := []openai.ChatCompletionToolUnionParam{}
		for _, tool := range tools {
			// Convert tool.Parameters to openai.FunctionParameters
			var funcParams openai.FunctionParameters
			if tool.Parameters != nil {
				if params, ok := tool.Parameters.(map[string]interface{}); ok {
					funcParams = openai.FunctionParameters(params)
				}
			}

			openaiTools = append(openaiTools, openai.ChatCompletionFunctionTool(openai.FunctionDefinitionParam{
				Name:        tool.Name,
				Description: openai.String(tool.Description),
				Parameters:  funcParams,
			}))
		}
		param.Tools = openaiTools
	}

	// Note: Response schema is NOT set initially when tools are present
	// because OpenAI doesn't support using both simultaneously.
	// The schema will be applied after all tool calls are complete.

	var resp *openai.ChatCompletion
	var err error

	// Loop to handle tool calls
	maxIterations := 10
	for iteration := range maxIterations {
		slog.Debug("tool calling iteration", slog.Int("iteration", iteration), slog.Int("message_count", len(param.Messages)))

		var opts []option.RequestOption
		if l.debugEnabled {
			opts = append(opts, option.WithDebugLog(nil))
		}

		if len(l.providers) > 0 {
			opts = append(opts, option.WithJSONSet("provider", map[string]any{
				"require_parameters": true,
				"order":              l.providers,
				"allow_fallbacks":    true,
			}))
		}

//		if l.top_k >= 0 {
//			opts = append(opts, option.WithJSONSet("top_k", l.top_k))
//		}

		resp, err = l.client.Chat.Completions.New(ctx, param, opts...)

		if err != nil {
			return "", fmt.Errorf("chat completion error: %v", err)
		}

		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("chat returned nothing")
		}

		choice := resp.Choices[0]
		slog.Debug("received response",
			slog.Int("iteration", iteration),
			slog.Int("tool_calls_count", len(choice.Message.ToolCalls)),
			slog.String("content", choice.Message.Content))

		// Check if the model wants to call a tool
		if len(choice.Message.ToolCalls) > 0 {
			slog.Debug("processing tool calls", slog.Int("count", len(choice.Message.ToolCalls)))
			// Add the assistant's message with tool calls to the conversation
			param.Messages = append(param.Messages, choice.Message.ToParam())

			// Execute each tool call
			for _, toolCall := range choice.Message.ToolCalls {
				toolName := toolCall.Function.Name
				toolArgs := toolCall.Function.Arguments

				slog.Debug("executing tool",
					slog.String("tool", toolName),
					slog.String("tool_call_id", toolCall.ID),
					slog.String("args", toolArgs))

				// Find the corresponding tool function
				var toolFunc func(args string) (string, error)
				for _, t := range tools {
					if t.Name == toolName {
						toolFunc = t.Function
						break
					}
				}

				if toolFunc == nil {
					slog.Error("tool not found", slog.String("tool", toolName))
					continue
				}

				result, err := toolFunc(toolArgs)
				if err != nil {
					slog.Error("error executing tool", slog.String("tool", toolName), slog.String("error", err.Error()))
					result = "could not run tool successfully for you"
				}

				slog.Debug("tool result",
					slog.String("tool", toolName),
					slog.String("tool_call_id", toolCall.ID),
					slog.String("result", result))

				// Add the tool result to the conversation
				param.Messages = append(param.Messages, openai.ToolMessage(result, toolCall.ID))
			}
			// Remove tools from params for the next iteration
			// and add response schema if configured
			param.Tools = nil
			if l.schema != nil {
				param.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
					OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{
						JSONSchema: *l.schema,
					},
				}
			}
			// Continue the loop to get the final response
			continue
		}

		// No tool calls in this iteration
		// If tools were available but not used, and schema is set, we need to
		// apply the schema and make another call to get formatted output
		if param.Tools != nil && l.schema != nil {
			slog.Debug("no tools called but schema required, applying schema for next iteration")
			// Add the assistant's message to conversation
			param.Messages = append(param.Messages, choice.Message.ToParam())
			// Remove tools and add schema
			param.Tools = nil
			param.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
				OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{
					JSONSchema: *l.schema,
				},
			}
			continue
		}

		// No more tool calls, return the final response
		slog.Debug("no tool calls, returning final response", slog.String("content", choice.Message.Content))
		return choice.Message.Content, nil
	}

	return "", fmt.Errorf("exceeded maximum tool call iterations")
}
