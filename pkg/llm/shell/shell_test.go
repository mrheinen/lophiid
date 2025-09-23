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
package shell

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"strings"
	"testing"
)

func TestRunCommand_NoExistingCommands(t *testing.T) {
	// Setup mock LLM manager
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"command_output": "total 8\ndrwxr-xr-x 2 root root 4096 Jan 1 12:00 .\ndrwxr-xr-x 3 root root 4096 Jan 1 12:00 ..", "hostname": "web-server-01", "working_directory": "/root", "username": "root"}`,
	}

	// Setup fake database client
	fakeDB := &database.FakeDatabaseClient{
		SessionExecutionContextToReturn: []models.SessionExecutionContext{}, // No previous commands
		ErrorToReturn:                   nil,
	}

	// Create shell client
	shellClient := NewShellClient(mockLLM, fakeDB)

	// Create test request
	req := &models.Request{
		ID:        123,
		SessionID: 456,
	}

	// Execute RunCommand
	result, err := shellClient.RunCommand(req, "ls -la")

	// Verify no error occurred
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result is not nil
	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// Verify the result contains expected values
	if result.SessionID != req.SessionID {
		t.Errorf("Expected SessionID %d, got %d", req.SessionID, result.SessionID)
	}

	if result.RequestID != req.ID {
		t.Errorf("Expected RequestID %d, got %d", req.ID, result.RequestID)
	}

	if result.Input != "ls -la" {
		t.Errorf("Expected Input 'ls -la', got '%s'", result.Input)
	}

	if result.EnvHostname != "web-server-01" {
		t.Errorf("Expected EnvHostname 'web-server-01', got '%s'", result.EnvHostname)
	}

	if result.EnvUser != "root" {
		t.Errorf("Expected EnvUser 'root', got '%s'", result.EnvUser)
	}

	if result.EnvCWD != "/root" {
		t.Errorf("Expected EnvCWD '/root', got '%s'", result.EnvCWD)
	}

	// Verify the LLM was called with the correct messages
	if len(mockLLM.LastReceivedMessages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(mockLLM.LastReceivedMessages))
	}

	if mockLLM.LastReceivedMessages[0].Role != "system" {
		t.Errorf("Expected first message role 'system', got '%s'", mockLLM.LastReceivedMessages[0].Role)
	}

	if mockLLM.LastReceivedMessages[1].Role != "user" {
		t.Errorf("Expected second message role 'user', got '%s'", mockLLM.LastReceivedMessages[1].Role)
	}

	if mockLLM.LastReceivedMessages[1].Content != "ls -la" {
		t.Errorf("Expected second message content 'ls -la', got '%s'", mockLLM.LastReceivedMessages[1].Content)
	}

	// Verify the database insert was called
	if fakeDB.LastDataModelSeen == nil {
		t.Error("Expected database Insert to be called")
	}
}

func TestRunCommand_WithExistingCommands(t *testing.T) {
	// Setup mock LLM manager
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"command_output": "myfile.txt", "hostname": "web-server-01", "working_directory": "/tmp", "username": "root"}`,
	}

	// Setup fake database client with existing commands
	existingCommands := []models.SessionExecutionContext{
		{
			ID:          1,
			SessionID:   456,
			RequestID:   100,
			EnvHostname: "web-server-01",
			EnvUser:     "root",
			EnvCWD:      "/tmp",
			Input:       "touch myfile.txt",
			Output:      "",
		},
		{
			ID:          2,
			SessionID:   456,
			RequestID:   101,
			EnvHostname: "web-server-01",
			EnvUser:     "root",
			EnvCWD:      "/tmp",
			Input:       "ls",
			Output:      "myfile.txt",
		},
	}

	fakeDB := &database.FakeDatabaseClient{
		SessionExecutionContextToReturn: existingCommands,
		ErrorToReturn:                   nil,
	}

	// Create shell client
	shellClient := NewShellClient(mockLLM, fakeDB)

	// Create test request
	req := &models.Request{
		ID:        123,
		SessionID: 456,
	}

	// Execute RunCommand
	result, err := shellClient.RunCommand(req, "ls myfile.txt")

	// Verify no error occurred
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Verify result is not nil
	if result == nil {
		t.Fatal("Expected result to be non-nil")
	}

	// Verify the LLM was called with the correct messages (system + previous commands + new command)
	expectedMessageCount := 1 + (len(existingCommands) * 2) + 1 // system + (user+assistant per existing command) + new user command
	if len(mockLLM.LastReceivedMessages) != expectedMessageCount {
		t.Errorf("Expected %d messages, got %d", expectedMessageCount, len(mockLLM.LastReceivedMessages))
	}

	// Verify system message includes environment variables from last command
	if mockLLM.LastReceivedMessages[0].Role != "system" {
		t.Errorf("Expected first message role 'system', got '%s'", mockLLM.LastReceivedMessages[0].Role)
	}

	systemMsg := mockLLM.LastReceivedMessages[0].Content
	if !strings.Contains(systemMsg, "/tmp") || !strings.Contains(systemMsg, "root") || !strings.Contains(systemMsg, "web-server-01") {
		t.Errorf("Expected system message to contain environment variables, got: %s", systemMsg)
	}

	// Verify the last message is the new command
	lastMsg := mockLLM.LastReceivedMessages[len(mockLLM.LastReceivedMessages)-1]
	if lastMsg.Role != "user" || lastMsg.Content != "ls myfile.txt" {
		t.Errorf("Expected last message to be user command 'ls myfile.txt', got role='%s' content='%s'", lastMsg.Role, lastMsg.Content)
	}
}

func TestRunCommand_LLMCompletionError(t *testing.T) {
	// Setup mock LLM manager with error
	mockLLM := &llm.MockLLMManager{
		ErrorToReturn: fmt.Errorf("LLM service unavailable"),
	}

	// Setup fake database client
	fakeDB := &database.FakeDatabaseClient{
		SessionExecutionContextToReturn: []models.SessionExecutionContext{},
		ErrorToReturn:                   nil,
	}

	// Create shell client
	shellClient := NewShellClient(mockLLM, fakeDB)

	// Create test request
	req := &models.Request{
		ID:        123,
		SessionID: 456,
	}

	// Execute RunCommand
	result, err := shellClient.RunCommand(req, "ls")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Verify result is nil
	if result != nil {
		t.Error("Expected result to be nil when LLM fails")
	}

	// Verify error message contains LLM error
	if !strings.Contains(err.Error(), "LLM service unavailable") {
		t.Errorf("Expected error to contain 'LLM service unavailable', got: %v", err)
	}
}

func TestRunCommand_JSONUnmarshalError(t *testing.T) {
	// Setup mock LLM manager with invalid JSON
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `invalid json response`,
	}

	// Setup fake database client
	fakeDB := &database.FakeDatabaseClient{
		SessionExecutionContextToReturn: []models.SessionExecutionContext{},
		ErrorToReturn:                   nil,
	}

	// Create shell client
	shellClient := NewShellClient(mockLLM, fakeDB)

	// Create test request
	req := &models.Request{
		ID:        123,
		SessionID: 456,
	}

	// Execute RunCommand
	result, err := shellClient.RunCommand(req, "ls")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Verify result is nil
	if result != nil {
		t.Error("Expected result to be nil when JSON parsing fails")
	}
}

func TestRunCommand_DatabaseInsertError(t *testing.T) {
	// Setup mock LLM manager
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"command_output": "test output", "hostname": "web-server-01", "working_directory": "/root", "username": "root"}`,
	}

	// Setup fake database client with insert error
	fakeDB := &database.FakeDatabaseClient{
		SessionExecutionContextToReturn: []models.SessionExecutionContext{},
		ErrorToReturn:                   fmt.Errorf("database insert failed"),
	}

	// Create shell client
	shellClient := NewShellClient(mockLLM, fakeDB)

	// Create test request
	req := &models.Request{
		ID:        123,
		SessionID: 456,
	}

	// Execute RunCommand
	result, err := shellClient.RunCommand(req, "ls")

	// Verify error occurred
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Verify result is nil
	if result != nil {
		t.Error("Expected result to be nil when database insert fails")
	}

	// Verify error message contains database error
	if !strings.Contains(err.Error(), "database insert failed") {
		t.Errorf("Expected error to contain 'database insert failed', got: %v", err)
	}
}
