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
package preprocess

import (
	"encoding/json"
	"errors"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/llm/shell"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func createTestMetrics() *PreprocessMetrics {
	reg := prometheus.NewRegistry()
	return CreatePreprocessMetrics(reg)
}

func TestProcess_NoPayload(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  false,
		PayloadType: "",
		Payload:     "",
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if result.HasPayload {
		t.Error("Expected HasPayload to be false")
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_ShellCommandPayload(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "SHELL_COMMAND",
		Payload:     "echo 'hello world'",
	}
	
	expectedOutput := "hello world"
	executionContext := &models.SessionExecutionContext{
		SessionID:   100,
		RequestID:   1,
		EnvHostname: "test-host",
		EnvCWD:      "/tmp",
		EnvUser:     "root",
		Input:       "echo 'hello world'",
		Output:      expectedOutput,
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	fakeShell.ContextToReturn = executionContext
	fakeShell.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET /?cmd=echo+hello HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if !result.HasPayload {
		t.Error("Expected HasPayload to be true")
	}
	
	if result.PayloadType != "SHELL_COMMAND" {
		t.Errorf("Expected PayloadType 'SHELL_COMMAND', got: %s", result.PayloadType)
	}
	
	if result.Payload != "echo 'hello world'" {
		t.Errorf("Expected Payload 'echo 'hello world'', got: %s", result.Payload)
	}
	
	if body != expectedOutput {
		t.Errorf("Expected body '%s', got: %s", expectedOutput, body)
	}
}

func TestProcess_FileAccessPayload(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "FILE_ACCESS",
		Payload:     "/etc/passwd",
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET /?file=/etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if !result.HasPayload {
		t.Error("Expected HasPayload to be true")
	}
	
	if result.PayloadType != "FILE_ACCESS" {
		t.Errorf("Expected PayloadType 'FILE_ACCESS', got: %s", result.PayloadType)
	}
	
	if result.Payload != "/etc/passwd" {
		t.Errorf("Expected Payload '/etc/passwd', got: %s", result.Payload)
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_UnknownPayloadType(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "UNKNOWN",
		Payload:     "some random payload",
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nsome data",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if !result.HasPayload {
		t.Error("Expected HasPayload to be true")
	}
	
	if result.PayloadType != "UNKNOWN" {
		t.Errorf("Expected PayloadType 'UNKNOWN', got: %s", result.PayloadType)
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_LLMError(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	expectedError := errors.New("LLM service unavailable")
	mockLLM.CompletionToReturn = ""
	mockLLM.ErrorToReturn = expectedError
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	
	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_InvalidJSON(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	mockLLM.CompletionToReturn = "this is not valid JSON"
	mockLLM.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
	
	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_ShellCommandError(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "SHELL_COMMAND",
		Payload:     "dangerous-command",
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	
	expectedError := errors.New("shell command execution failed")
	fakeShell.ContextToReturn = nil
	fakeShell.ErrorToReturn = expectedError
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET /?cmd=dangerous-command HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	
	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}
	
	if body != "" {
		t.Errorf("Expected empty body, got: %s", body)
	}
}

func TestProcess_MultipleShellCommands(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	
	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "SHELL_COMMAND",
		Payload:     "ls -la && pwd",
	}
	
	expectedOutput := "total 8\ndrwxr-xr-x 2 root root 4096 Jan 1 00:00 .\ndrwxr-xr-x 3 root root 4096 Jan 1 00:00 ..\n/tmp"
	executionContext := &models.SessionExecutionContext{
		SessionID:   100,
		RequestID:   1,
		EnvHostname: "web-server",
		EnvCWD:      "/tmp",
		EnvUser:     "www-data",
		Input:       "ls -la && pwd",
		Output:      expectedOutput,
	}
	
	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	fakeShell.ContextToReturn = executionContext
	fakeShell.ErrorToReturn = nil
	
	preprocess := NewPreProcess(mockLLM, fakeShell, metrics)
	
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       "GET /?cmd=ls+-la+%26%26+pwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
	}
	
	// Execute
	result, body, err := preprocess.Process(req)
	
	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	if !result.HasPayload {
		t.Error("Expected HasPayload to be true")
	}
	
	if result.PayloadType != "SHELL_COMMAND" {
		t.Errorf("Expected PayloadType 'SHELL_COMMAND', got: %s", result.PayloadType)
	}
	
	if body != expectedOutput {
		t.Errorf("Expected body '%s', got: %s", expectedOutput, body)
	}
}
