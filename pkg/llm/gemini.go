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

	"google.golang.org/genai"
)

type GeminiLLMClient struct {
	model          string
	promptTemplate string
	client         *genai.Client
	maxContextSize int64
}

func NewGeminiLLMMClient(apiKey string, promptTemplate string, model string, maxContextSize int64) *GeminiLLMClient {

	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})

	if err != nil {
		slog.Error("failed to create Gemini client", slog.String("error", err.Error()))
		return nil
	}

	return &GeminiLLMClient{
		model:          model,
		promptTemplate: promptTemplate,
		maxContextSize: maxContextSize,
		client:         client,
	}
}

func (g *GeminiLLMClient) LoadedModel() string {
	return g.model
}

func (g *GeminiLLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	finalPrompt := truncatePrompt(fmt.Sprintf(g.promptTemplate, prompt), g.maxContextSize)
	result, err := g.client.Models.GenerateContent(ctx, g.model, genai.Text(finalPrompt), nil)

	if err != nil {
		return "", fmt.Errorf("failed to generate completion: %w", err)
	}

	return result.Text(), err
}
