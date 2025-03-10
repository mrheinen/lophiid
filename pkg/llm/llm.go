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
	"fmt"
	"log/slog"

	openai "github.com/sashabaranov/go-openai"
)

type OpenAIClientInterface interface {
	CreateChatCompletion(ctx context.Context, request openai.ChatCompletionRequest) (response openai.ChatCompletionResponse, err error)
}

type LLMClient interface {
	Complete(ctx context.Context, prompt string) (string, error)
	LoadedModel() string
}

type MockLLMClient struct {
	CompletionToReturn string
	ErrorToReturn      error
}

func (m *MockLLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	return m.CompletionToReturn, m.ErrorToReturn
}

func (m *MockLLMClient) LoadedModel() string {
	return "gpt-3.5-turbo"
}

type OpenAILLMClient struct {
	client      *openai.Client
	apiEndpoint string // E.g. http://localhost:8000/v1
	Model       string
	// promptTemplate is used to construct the prompt. It needs to contain a
	// single %s at a location where the request prompt needs to go.
	promptTemplate string
}

// NewOpenAILLMClientWithModel creates a new OpenAILLMClient with the given
// model.
func NewOpenAILLMClientWithModel(apiKey string, apiEndpoint string, promptTemplate string, model string) *OpenAILLMClient {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = apiEndpoint
	client := openai.NewClientWithConfig(config)

	ret := &OpenAILLMClient{
		client:         client,
		apiEndpoint:    apiEndpoint,
		promptTemplate: promptTemplate,
		Model:          model,
	}

	models, err := client.ListModels(context.Background())
	if err != nil {
		slog.Error("could not list models", slog.String("error", err.Error()))
		return nil
	}

	for _, m := range models.Models {
		if m.ID == model {
			return ret
		}
	}

	slog.Error("could not find model", slog.String("model", model))
	return nil

}

// NewOpenAILLMClient creates a new OpenAILLMClient and auto selects a model
// from the API. Use this when talking with an API that only has one model.
func NewOpenAILLMClient(apiKey string, apiEndpoint string, promptTemplate string) *OpenAILLMClient {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = apiEndpoint
	client := openai.NewClientWithConfig(config)

	ret := &OpenAILLMClient{
		client:         client,
		apiEndpoint:    apiEndpoint,
		promptTemplate: promptTemplate,
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
	models, err := l.client.ListModels(context.Background())
	if err != nil {
		return fmt.Errorf("ListModels error: %w", err)
	}

	if len(models.Models) == 0 {
		return fmt.Errorf("no models found")
	}

	if len(models.Models) > 1 {
		slog.Warn("Found multiple models! Using the first.", slog.String("model", models.Models[0].ID))
	}

	l.Model = models.Models[0].ID
	return nil
}

func (l *OpenAILLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	resp, err := l.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: l.Model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: fmt.Sprintf(l.promptTemplate, prompt),
				},
			},
		},
	)

	if err != nil {
		return "", fmt.Errorf("ChatCompletion error: %v", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("chat returned nothing: %v", err)
	} else {
		return resp.Choices[0].Message.Content, nil
	}

}
