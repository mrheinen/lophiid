// Lophiid distributed honeypot
// Copyright (C) 2023-2026 Niels Heinen
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
package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLLMSummarizer_Summarize_Success(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"name": "Test Campaign", "summary": "A test campaign summary.", "severity": "HIGH"}`,
	}

	s, err := NewLLMSummarizer(mockLLM, "")
	require.NoError(t, err)
	name, summary, severity, err := s.Summarize(context.Background(), json.RawMessage(`{"timeline":{}}`))
	require.NoError(t, err)

	assert.Equal(t, "Test Campaign", name)
	assert.Equal(t, "A test campaign summary.", summary)
	assert.Equal(t, constants.CampaignSeverityHigh, severity)
}

func TestLLMSummarizer_Summarize_InvalidSeverity(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"name": "Test", "summary": "Test.", "severity": "UNKNOWN"}`,
	}

	s, err := NewLLMSummarizer(mockLLM, "")
	require.NoError(t, err)
	_, _, severity, err := s.Summarize(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	assert.Equal(t, constants.CampaignSeverityLow, severity, "invalid severity should default to LOW")
}

func TestLLMSummarizer_Summarize_LLMError(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		ErrorToReturn: errors.New("LLM unavailable"),
	}

	s, err := NewLLMSummarizer(mockLLM, "")
	require.NoError(t, err)
	_, _, _, err = s.Summarize(context.Background(), json.RawMessage(`{}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LLM completion failed")
}

func TestLLMSummarizer_Summarize_MalformedJSON(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: "This is not JSON at all",
	}

	s, err := NewLLMSummarizer(mockLLM, "")
	require.NoError(t, err)
	_, _, _, err = s.Summarize(context.Background(), json.RawMessage(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing LLM response")
}

func TestLLMSummarizer_Summarize_CustomPrompt(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"name": "Custom", "summary": "Custom prompt used.", "severity": "LOW"}`,
	}

	customPrompt := "Custom prompt: %s"
	s, err := NewLLMSummarizer(mockLLM, customPrompt)
	require.NoError(t, err)
	_, _, _, err = s.Summarize(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)

	assert.Contains(t, mockLLM.LastReceivedPrompt, "Custom prompt:")
}

func TestNoOpSummarizer(t *testing.T) {
	s := &NoOpSummarizer{}
	name, summary, severity, err := s.Summarize(context.Background(), json.RawMessage(`{}`))
	require.NoError(t, err)
	assert.Empty(t, name)
	assert.Empty(t, summary)
	assert.Empty(t, severity)
}

func TestParseLLMResponse_ValidJSON(t *testing.T) {
	name, summary, severity, err := parseLLMResponse(`{"name": "N", "summary": "S", "severity": "HIGH"}`)
	require.NoError(t, err)
	assert.Equal(t, "N", name)
	assert.Equal(t, "S", summary)
	assert.Equal(t, constants.CampaignSeverityHigh, severity)
}

func TestParseLLMResponse_NoJSON(t *testing.T) {
	_, _, _, err := parseLLMResponse("plain text")
	assert.Error(t, err)
}

func TestParseLLMResponse_EmptyObject(t *testing.T) {
	name, summary, severity, err := parseLLMResponse(`{}`)
	require.NoError(t, err)
	assert.Empty(t, name)
	assert.Empty(t, summary)
	assert.Empty(t, severity)
}
