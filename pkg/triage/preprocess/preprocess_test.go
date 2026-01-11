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
	"lophiid/pkg/llm/code"
	"lophiid/pkg/llm/file"
	"lophiid/pkg/llm/shell"
	"lophiid/pkg/llm/sql"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	fakeFileEmu := &file.FakeFileAccessEmulator{}
	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}

	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if pRes != nil {
		t.Error("Expected pRes to be nil")
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
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	fakeFileEmu := &file.FakeFileAccessEmulator{}
	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}

	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET /?cmd=echo+hello HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if pRes.Output != expectedOutput {
		t.Errorf("Expected body '%s', got: %s", expectedOutput, pRes.Output)
	}
}

func TestProcess_SqlInjectionPayload(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	fakeFileEmu := &file.FakeFileAccessEmulator{}
	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	metrics := createTestMetrics()

	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "SQL_INJECTION",
		Payload:     "' OR 1=1 --",
	}

	sqlOutput := &sql.SqlInjectionOutput{
		Output:  "id,name\n1,admin\n2,user",
		IsBlind: false,
		DelayMs: 0,
	}
	fakeSqlEmu.OutputToReturn = sqlOutput

	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil

	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET /?id=' OR 1=1 -- HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if result.PayloadType != "SQL_INJECTION" {
		t.Errorf("Expected PayloadType 'SQL_INJECTION', got: %s", result.PayloadType)
	}

	if result.Payload != "' OR 1=1 --" {
		t.Errorf("Expected Payload '' OR 1=1 --', got: %s", result.Payload)
	}

	if pRes == nil {
		t.Errorf("Expected payload response, got nil")
	} else {
		if pRes.Output != "id,name\n1,admin\n2,user" {
			t.Errorf("Expected output 'id,name\n1,admin\n2,user', got: %s", pRes.Output)
		}
		if pRes.SqlIsBlind {
			t.Error("Expected SqlIsBlind to be false")
		}
		if pRes.SqlDelayMs != 0 {
			t.Errorf("Expected SqlDelayMs 0, got: %d", pRes.SqlDelayMs)
		}
	}
}

func TestProcess_FileAccessPayload(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	fakeFileEmu := &file.FakeFileAccessEmulator{}
	metrics := createTestMetrics()

	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "FILE_ACCESS",
		Payload:     "/etc/passwd",
	}

	fakeFileEmu.ContentToReturn = "root:x:0:0:root:/root:/bin/bash"

	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET /?file=/etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if pRes == nil {
		t.Errorf("Expected payload response, got nil")
	} else if pRes.Output != "root:x:0:0:root:/root:/bin/bash" {
		t.Errorf("Expected body 'root:x:0:0:root:/root:/bin/bash', got: %s", pRes.Output)
	}
}

func TestProcess_UnknownPayloadType(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	metrics := createTestMetrics()

	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "UNKNOWN",
		Payload:     "some random payload",
	}

	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\nsome data"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if pRes != nil {
		t.Errorf("Expected empty body, got: %+v", pRes)
	}
}

func TestProcess_LLMError(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	metrics := createTestMetrics()

	expectedError := errors.New("LLM service unavailable")
	mockLLM.CompletionToReturn = ""
	mockLLM.ErrorToReturn = expectedError
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

	// Verify
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}

	if pRes != nil {
		t.Errorf("Expected empty body, got: %+v", pRes)
	}
}

func TestProcess_InvalidJSON(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	metrics := createTestMetrics()

	mockLLM.CompletionToReturn = "this is not valid JSON"
	mockLLM.ErrorToReturn = nil
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

	// Verify
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}

	if pRes != nil {
		t.Errorf("Expected empty body, got: %+v", pRes)
	}
}

func TestProcess_ShellCommandError(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	metrics := createTestMetrics()
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}

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
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET /?cmd=dangerous-command HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

	// Verify
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if result != nil {
		t.Errorf("Expected nil result, got: %v", result)
	}

	if pRes != nil {
		t.Errorf("Expected empty body, got: %+v", pRes)
	}
}

func TestProcess_MultipleShellCommands(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
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
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte("GET /?cmd=ls+-la+%26%26+pwd HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	// Execute
	result, pRes, err := preprocess.Process(req)

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

	if pRes.Output != expectedOutput {
		t.Errorf("Expected body '%s', got: %s", expectedOutput, pRes.Output)
	}
}

func TestProcess_FileUploadPayload(t *testing.T) {
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	fakeFileEmu := &file.FakeFileAccessEmulator{}
	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	metrics := createTestMetrics()

	preprocessResult := PreProcessResult{
		HasPayload:  true,
		PayloadType: "FILE_UPLOAD",
		Payload:     "<?php echo 'pwned'; ?>",
		Target:      "/var/www/html/shell.php",
	}

	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil

	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	req := &models.Request{
		ID:        42,
		SessionID: 100,
		SourceIP:  "192.168.1.55",
		Raw:       []byte("POST /upload.php HTTP/1.1\r\nHost: example.com\r\n\r\n<?php echo 'pwned'; ?>"),
	}

	result, pRes, err := preprocess.Process(req)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.HasPayload)
	assert.Equal(t, "FILE_UPLOAD", result.PayloadType)
	require.NotNil(t, pRes)
	require.NotNil(t, pRes.TmpContentRule)
	assert.Equal(t, "shell.php", pRes.TmpContentRule.Rule.Uri)
	assert.Equal(t, "<?php echo 'pwned'; ?>", string(pRes.TmpContentRule.Content.Data))

	// Verify AllowFromNet is set to the /24 network of the source IP
	require.NotNil(t, pRes.TmpContentRule.Rule.AllowFromNet)
	assert.Equal(t, "192.168.1.0", *pRes.TmpContentRule.Rule.AllowFromNet)

	assert.Equal(t, int64(42, pRes.TmpContentRule.Rule.AppID)
}

func TestProcess_FileUploadInvalidFilename(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{"empty filename", ""},
		{"filename too short", "a.p"},
		{"filename too long", strings.Repeat("a", 2049) + ".php"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockLLM := &llm.MockLLMManager{}
			fakeShell := &shell.FakeShellClient{}
			fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
			fakeFileEmu := &file.FakeFileAccessEmulator{}
			fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
			metrics := createTestMetrics()

			preprocessResult := PreProcessResult{
				HasPayload:  true,
				PayloadType: "FILE_UPLOAD",
				Payload:     "<?php echo 'pwned'; ?>",
				Target:      tc.target,
			}

			jsonResult, _ := json.Marshal(preprocessResult)
			mockLLM.CompletionToReturn = string(jsonResult)
			mockLLM.ErrorToReturn = nil

			preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

			req := &models.Request{
				ID:        1,
				SessionID: 100,
				Raw:       []byte("POST /upload.php HTTP/1.1\r\nHost: example.com\r\n\r\n<?php echo 'pwned'; ?>"),
			}

			result, pRes, err := preprocess.Process(req)

			require.NoError(t, err)
			assert.Nil(t, result)
			assert.Nil(t, pRes)
		})
	}
}

func TestComplete_HostHeaderRemoval(t *testing.T) {
	// Setup
	mockLLM := &llm.MockLLMManager{}
	fakeShell := &shell.FakeShellClient{}
	fakeCodeEmu := &code.FakeCodeSnippetEmulator{}
	metrics := createTestMetrics()

	preprocessResult := PreProcessResult{
		HasPayload:  false,
		PayloadType: "",
		Payload:     "",
	}

	jsonResult, _ := json.Marshal(preprocessResult)
	mockLLM.CompletionToReturn = string(jsonResult)
	mockLLM.ErrorToReturn = nil
	fakeFileEmu := &file.FakeFileAccessEmulator{}

	fakeSqlEmu := &sql.FakeSqlInjectionEmulator{}
	preprocess := NewPreProcess(mockLLM, fakeShell, fakeCodeEmu, fakeFileEmu, fakeSqlEmu, metrics)

	reqRaw := "GET / HTTP/1.1\nHost: example.com\nUser-Agent: TestBot\n\n"
	req := &models.Request{
		ID:        1,
		SessionID: 100,
		Raw:       []byte(reqRaw),
	}

	// Execute
	_, err := preprocess.Complete(req)

	// Verify
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if strings.Contains(mockLLM.LastReceivedPrompt, "Host:") {
		t.Error("Expected Host header to be removed from prompt")
	}

	if !strings.Contains(mockLLM.LastReceivedPrompt, "User-Agent: TestBot") {
		t.Error("Expected User-Agent header to be preserved in prompt")
	}

	if !strings.Contains(mockLLM.LastReceivedPrompt, "GET / HTTP/1.1") {
		t.Error("Expected request line to be preserved in prompt")
	}
}
