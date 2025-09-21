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

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
)

type OpenAILLMClient struct {
	client      *openai.Client
	apiEndpoint string // E.g. http://localhost:8000/v1
	Model       string
	// promptTemplate is used to construct the prompt. It needs to contain a
	// single %s at a location where the request prompt needs to go.
	promptTemplate string
	// maxContextSize is the maximum number of characters allowed in the context
	maxContextSize int64
}

// NewOpenAILLMClientWithModel creates a new OpenAILLMClient with the given
// model and maximum context size.
func NewOpenAILLMClientWithModel(apiKey string, apiEndpoint string, promptTemplate string, model string, maxContextSize int64) *OpenAILLMClient {
	client := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(apiEndpoint),
	)

	ret := &OpenAILLMClient{
		client:         &client,
		apiEndpoint:    apiEndpoint,
		promptTemplate: promptTemplate,
		Model:          model,
		maxContextSize: maxContextSize,
	}

	ctx, _ := context.WithTimeout(context.Background(), time.Second*30)
	models, err := client.Models.List(ctx)
	if err != nil {
		slog.Error("error listing models", slog.String("error", err.Error()))
		return nil
	}

	for _, m := range models.Data {
		if m.ID == model {
			return ret
		}
	}

	slog.Error("could not find model", slog.String("model", model))
	return nil
}

// NewOpenAILLMClient creates a new OpenAILLMClient and auto selects a model
// from the API. Use this when talking with an API that only has one model.
func NewOpenAILLMClient(apiKey string, apiEndpoint string, promptTemplate string, maxContextSize int64) *OpenAILLMClient {

	client := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL(apiEndpoint),
	)

	ret := &OpenAILLMClient{
		client:         &client,
		apiEndpoint:    apiEndpoint,
		promptTemplate: promptTemplate,
		maxContextSize: maxContextSize,
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

// SelectModel queries the OpenAI API for models and selects the first model.
func (l *OpenAILLMClient) SelectModel() error {
	ctx, _ := context.WithTimeout(context.Background(), time.Second*30)
	models, err := l.client.Models.List(ctx)
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
	truncatedPrompt := truncatePrompt(fmt.Sprintf(l.promptTemplate, prompt), int64(l.maxContextSize))

	msgs := []LLMMessage{
		{
			Role:    constants.LLMClientMessageUser,
			Content: truncatedPrompt,
		},
	}

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

	for i := range msgs {
		switch msgs[i].Role {
		case constants.LLMClientMessageUser:
			param.Messages = append(param.Messages, openai.UserMessage(msgs[i].Content))
		case constants.LLMClientMessageSystem:
			param.Messages = append(param.Messages, openai.SystemMessage(msgs[i].Content))
		default:
			return "", fmt.Errorf("unknown role: %s", msgs[i].Role)
		}
	}

	resp, err := l.client.Chat.Completions.New(ctx, param)

	if err != nil {
		return "", fmt.Errorf("chat completion error: %v", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("chat returned nothing")
	}

	return resp.Choices[0].Message.Content, nil
}
