package sql

import (
	"fmt"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"strings"
	"testing"
)

func TestEmulate_IncludesRequestInPrompt(t *testing.T) {
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: `{"output": "result", "is_blind": false, "delay_ms": 0}`,
	}

	emulator := NewSqlInjectionEmulator(mockLLM)
	req := &models.Request{
		Raw: []byte("GET /?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}
	payload := "' OR 1=1 --"

	_, err := emulator.Emulate(req, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mockLLM.LastReceivedMessages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(mockLLM.LastReceivedMessages))
	}

	userMsg := mockLLM.LastReceivedMessages[1].Content
	if !strings.Contains(userMsg, payload) {
		t.Errorf("expected user message to contain payload")
	}
	if !strings.Contains(userMsg, "GET /?id=1 HTTP/1.1") {
		t.Errorf("expected user message to contain request raw data")
	}
}

func TestEmulate_ParsesResponse(t *testing.T) {
	expectedOutput := "id,name\\n1,admin"
	jsonOutput := fmt.Sprintf(`{"output": "%s", "is_blind": true, "delay_ms": 100}`, expectedOutput)
	mockLLM := &llm.MockLLMManager{
		CompletionToReturn: jsonOutput,
	}

	emulator := NewSqlInjectionEmulator(mockLLM)
	req := &models.Request{}
	payload := "payload"

	result, err := emulator.Emulate(req, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The emulator unmarshals the JSON, so the \\n becomes \n in the result string
	expectedDecodedOutput := "id,name\n1,admin"
	if result.Output != expectedDecodedOutput {
		t.Errorf("expected output %q, got %q", expectedDecodedOutput, result.Output)
	}
	if !result.IsBlind {
		t.Error("expected IsBlind to be true")
	}
	if result.DelayMs != 100 {
		t.Errorf("expected DelayMs 100, got %d", result.DelayMs)
	}
}
