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
	"lophiid/pkg/rulegeneration/tools"
	"lophiid/pkg/rulegeneration/workflows"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSearch is a minimal tools.SearchProvider for agent-level tests.
type fakeSearch struct{}

func (f *fakeSearch) Search(_ context.Context, _ string, _ int) ([]tools.SearchResult, error) {
	return nil, nil
}

func newTestAgent(llmMgr llm.LLMManagerInterface, db database.DatabaseClient, req models.Request, desc models.RequestDescription) *Agent {
	webTools := tools.NewWebTools(&fakeSearch{})
	githubTools := tools.NewGithubTools("", 5)
	dbTools := tools.NewDatabaseTools(db, true)
	toolset := workflows.NewRuleCreationToolSet(webTools, githubTools, dbTools)
	wf := workflows.NewRuleCreationWorkflow(llmMgr, toolset, req, desc)
	return NewAgent(wf)
}

func TestAgent_Process_Success(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: "Draft created successfully.",
	}
	fakeDB := &database.FakeDatabaseClient{}

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

	agent := newTestAgent(mockLLM, fakeDB, req, desc)
	err := agent.Process(context.Background())
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

	req := models.Request{ID: 2, Method: "POST", Uri: "/wp-login.php"}
	desc := models.RequestDescription{AIMalicious: "yes", AIDescription: "brute force"}

	agent := newTestAgent(mockLLM, fakeDB, req, desc)
	err := agent.Process(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "LLM unavailable")
}
