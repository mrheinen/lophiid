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

// This file contains unit tests for the CodeSnippetEmulator.Emulate method.
// Test coverage includes:
// - Database errors: Verifies graceful handling when DB insert fails
// - JSON unmarshal errors: Tests behavior with invalid JSON responses
// - LLM manager errors: Validates error propagation from LLM failures
// - Successful execution: Tests the happy path with valid responses
package code

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/llm/tools"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testRequest creates a minimal test Request
func testRequest() *models.Request {
	return &models.Request{
		ID:        123,
		SessionID: 456,
	}
}

// testEmulator creates a CodeSnippetEmulator with mocks
func testEmulator(llmManager *llm.MockLLMManager, dbClient *database.FakeDatabaseClient, shellClient shell.ShellClientInterface) *CodeSnippetEmulator {
	return &CodeSnippetEmulator{
		llmManager:  llmManager,
		dbClient:    dbClient,
		toolSet:     tools.NewCodeToolSet(shellClient),
	}
}

func TestEmulate_Success(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"stdout": "Hello World", "headers": "Content-Type: text/html", "language": "python"}`,
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{
		ErrorToReturn: nil,
	}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "print('Hello World')")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Hello World", string(result.Stdout))
	assert.Equal(t, "Content-Type: text/html", result.Headers)
	assert.Equal(t, "python", result.Language)
	assert.Equal(t, req.ID, result.RequestID)
	assert.Equal(t, req.SessionID, result.SessionID)
	assert.Equal(t, "test-model", result.SourceModel)
}

func TestEmulate_LLMManagerError(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: "",
		ErrorToReturn:      fmt.Errorf("llm api failure"),
	}
	mockDB := &database.FakeDatabaseClient{}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "some code")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "error completing prompt")
	assert.Contains(t, err.Error(), "llm api failure")
}

func TestEmulate_JSONUnmarshalError(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{invalid json: this is not valid}`,
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "some code")

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestEmulate_DatabaseError(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"stdout": "output", "headers": "", "language": "bash"}`,
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{
		ErrorToReturn: fmt.Errorf("database connection failed"),
	}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "echo 'test'")

	// Database errors should NOT fail the operation
	// The method logs the error but continues
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "output", string(result.Stdout))
	assert.Equal(t, "bash", result.Language)
}

func TestEmulate_JSONWithMarkdownWrapper(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: "```json\n{\"stdout\": \"test output\", \"headers\": \"\", \"language\": \"c\"}\n```",
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "printf(\"test\");")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test output", string(result.Stdout))
	assert.Equal(t, "c", result.Language)
}

func TestEmulate_EmptyStdout(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"stdout": "", "headers": "", "language": "java"}`,
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{}
	mockShell := &shell.FakeShellClient{}

	emulator := testEmulator(mockLLM, mockDB, mockShell)
	req := testRequest()

	result, err := emulator.Emulate(req, "// no output")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result.Stdout)
	assert.Equal(t, "java", result.Language)
}


func TestEmulate_WithNilShellClient(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"stdout": "output", "headers": "", "language": "python"}`,
		ErrorToReturn:      nil,
	}
	mockDB := &database.FakeDatabaseClient{}

	// Create emulator with nil shellClient
	emulator := testEmulator(mockLLM, mockDB, nil)
	req := testRequest()

	result, err := emulator.Emulate(req, "print('test')")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "output", string(result.Stdout))
}
