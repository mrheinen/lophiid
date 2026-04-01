// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package rulegeneration

import (
	"context"
	"fmt"
	"testing"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAgent(llmMgr llm.LLMManagerInterface, db database.DatabaseClient) *Agent {
	toolSet := NewToolSet(context.Background(), db, &fakeSearch{}, 1, true)
	return NewAgent(llmMgr, toolSet)
}

func TestAgent_Process_Success(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: "Draft created successfully.",
	}
	fakeDB := &database.FakeDatabaseClient{}
	agent := newTestAgent(mockLLM, fakeDB)

	req := models.Request{
		ID:     1,
		Method: "GET",
		Uri:    "/struts2-showcase/index.action",
	}
	desc := models.RequestDescription{
		AIMalicious:         "yes",
		AIDescription:       "Possible Apache Struts RCE via OGNL injection",
		AIApplication:       "Apache Struts",
		AIVulnerabilityType: "RCE",
		AICVE:               "CVE-2017-5638",
	}

	err := agent.Process(context.Background(), req, desc)
	require.NoError(t, err)

	// Verify the LLM received both system and user messages.
	msgs := mockLLM.LastReceivedMessages
	require.Len(t, msgs, 2)
	assert.Equal(t, "system", msgs[0].Role)
	assert.Equal(t, "user", msgs[1].Role)
	assert.Contains(t, msgs[1].Content, "/struts2-showcase/index.action")
	assert.Contains(t, msgs[1].Content, "CVE-2017-5638")
}

func TestAgent_Process_LLMError(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		ErrorToReturn: fmt.Errorf("LLM unavailable"),
	}
	fakeDB := &database.FakeDatabaseClient{}
	agent := newTestAgent(mockLLM, fakeDB)

	req := models.Request{ID: 2, Method: "POST", Uri: "/wp-login.php"}
	desc := models.RequestDescription{AIMalicious: "yes", AIDescription: "brute force"}

	err := agent.Process(context.Background(), req, desc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LLM unavailable")
}

func TestBuildUserMessage_IncludesBody(t *testing.T) {
	req := models.Request{
		Method: "POST",
		Uri:    "/cgi-bin/test.cgi",
		Body:   []byte("param=value&exploit=yes"),
	}
	desc := models.RequestDescription{
		AIMalicious:   "yes",
		AIDescription: "CGI injection",
	}

	msg := buildUserMessage(req, desc)
	assert.Contains(t, msg, "param=value&exploit=yes")
	assert.Contains(t, msg, "/cgi-bin/test.cgi")
	assert.Contains(t, msg, "CGI injection")
}

func TestBuildUserMessage_TruncatesLongBody(t *testing.T) {
	longBody := make([]byte, 4096)
	for i := range longBody {
		longBody[i] = 'A'
	}
	req := models.Request{
		Method: "POST",
		Uri:    "/test",
		Body:   longBody,
	}
	desc := models.RequestDescription{}

	msg := buildUserMessage(req, desc)
	// Only first 2048 bytes should appear
	assert.Contains(t, msg, "Request body (first 2048 bytes)")
}

func TestNewAgentFromConfig_UnknownProvider(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	mockLLM := &llm.MockLLMManager{}

	_, err := NewAgentFromConfig(
		context.Background(),
		fakeDB,
		mockLLM,
		WebSearchConfig{Provider: "unknown-engine", APIKey: "key"},
		1,
		false,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown search provider")
}

func TestNewAgentFromConfig_MissingTavilyKey(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	mockLLM := &llm.MockLLMManager{}

	_, err := NewAgentFromConfig(
		context.Background(),
		fakeDB,
		mockLLM,
		WebSearchConfig{Provider: "tavily", APIKey: ""},
		1,
		false,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}
