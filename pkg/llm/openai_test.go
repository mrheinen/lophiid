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

// This file contains unit tests for the OpenAILLMClient.CompleteWithTools method.
// Test coverage includes:
// - No tools defined: Validates normal completion without tool support
// - Tool execution errors: Ensures errors from tools are handled gracefully
// - Undefined tool calls: Tests behavior when LLM requests a non-existent tool
// - Max iterations exceeded: Verifies the 10-iteration limit is enforced
// - Successful tool execution: Tests normal tool calling workflow
// - Multiple tool calls: Validates handling of multiple tools in one response
// - Invalid last message: Ensures validation of message role requirements
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"lophiid/pkg/util/constants"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/stretchr/testify/assert"
)

// testClient creates an OpenAILLMClient configured to use a test server
func testClient(t *testing.T, handler http.HandlerFunc) *OpenAILLMClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := openai.NewClient(
		option.WithAPIKey("test-key"),
		option.WithBaseURL(server.URL),
	)

	return &OpenAILLMClient{
		client:         &client,
		systemPrompt:   "test system prompt",
		Model:          "test-model",
		maxContextSize: 1000,
	}
}

// chatCompletionResponse creates a mock OpenAI chat completion response
func chatCompletionResponse(content string, toolCalls []map[string]interface{}) string {
	message := map[string]interface{}{
		"role":    "assistant",
		"content": content,
	}

	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	response := map[string]interface{}{
		"id":      "test-id",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "test-model",
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"message":       message,
				"finish_reason": "stop",
			},
		},
	}

	data, _ := json.Marshal(response)
	return string(data)
}

// toolCall creates a mock tool call structure
func toolCall(id, name, args string) map[string]interface{} {
	return map[string]interface{}{
		"id":   id,
		"type": "function",
		"function": map[string]interface{}{
			"name":      name,
			"arguments": args,
		},
	}
}

// testMessages returns a basic set of test messages
func testMessages() []LLMMessage {
	return []LLMMessage{
		{
			Role:    constants.LLMClientMessageUser,
			Content: "test prompt",
		},
	}
}

func TestCompleteWithTools_NoTools(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		assert.Equal(t, "/chat/completions", r.URL.Path)
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(chatCompletionResponse("final response", nil)))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	result, err := client.CompleteWithTools(ctx, msgs, nil)
	assert.NoError(t, err)
	assert.Equal(t, "final response", result)
	assert.Equal(t, 1, callCount)
}

func TestCompleteWithTools_ToolError(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// First call: return tool call
		if callCount == 1 {
			w.Write([]byte(chatCompletionResponse("", []map[string]interface{}{
				toolCall("call-1", "test_tool", `{"arg": "value"}`),
			})))
			return
		}

		// Second call: return final response
		w.Write([]byte(chatCompletionResponse("final response after tool error", nil)))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	toolErrorExecuted := false
	tools := []LLMTool{
		{
			Name:        "test_tool",
			Description: "test tool that errors",
			Function: func(args string) (string, error) {
				toolErrorExecuted = true
				return "", fmt.Errorf("tool execution failed")
			},
		},
	}

	result, err := client.CompleteWithTools(ctx, msgs, tools)
	assert.NoError(t, err)
	assert.True(t, toolErrorExecuted, "tool function was not executed")
	assert.Equal(t, "final response after tool error", result)
	assert.Equal(t, 2, callCount)
}

func TestCompleteWithTools_UndefinedTool(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// First call: return tool call for undefined tool
		if callCount == 1 {
			w.Write([]byte(chatCompletionResponse("", []map[string]interface{}{
				toolCall("call-1", "undefined_tool", `{"arg": "value"}`),
			})))
			return
		}

		// Second call: return final response
		w.Write([]byte(chatCompletionResponse("response after undefined tool", nil)))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	definedToolExecuted := false
	tools := []LLMTool{
		{
			Name:        "defined_tool",
			Description: "a defined tool",
			Function: func(args string) (string, error) {
				definedToolExecuted = true
				return "result", nil
			},
		},
	}

	result, err := client.CompleteWithTools(ctx, msgs, tools)
	assert.NoError(t, err)
	assert.False(t, definedToolExecuted, "defined tool should not have been executed")
	assert.Equal(t, "response after undefined tool", result)
	assert.Equal(t, 2, callCount)
}

func TestCompleteWithTools_MaxIterationsExceeded(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Always return a tool call to force max iterations
		w.Write([]byte(chatCompletionResponse("", []map[string]interface{}{
			toolCall(fmt.Sprintf("call-%d", callCount), "recursive_tool", `{"iteration": 1}`),
		})))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	executionCount := 0
	tools := []LLMTool{
		{
			Name:        "recursive_tool",
			Description: "tool that keeps getting called",
			Function: func(args string) (string, error) {
				executionCount++
				return "continue", nil
			},
		},
	}

	result, err := client.CompleteWithTools(ctx, msgs, tools)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded maximum tool call iterations")
	assert.Empty(t, result)
	assert.Equal(t, 10, callCount, "should make exactly 10 API calls (maxIterations)")
	assert.Equal(t, 10, executionCount, "tool should be executed 10 times")
}

func TestCompleteWithTools_SuccessfulToolExecution(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// First call: return tool call
		if callCount == 1 {
			w.Write([]byte(chatCompletionResponse("", []map[string]interface{}{
				toolCall("call-1", "calculator", `{"operation": "add", "a": 5, "b": 3}`),
			})))
			return
		}

		// Second call: return final response
		w.Write([]byte(chatCompletionResponse("The answer is 8", nil)))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	toolExecuted := false
	var receivedArgs string
	tools := []LLMTool{
		{
			Name:        "calculator",
			Description: "performs calculations",
			Function: func(args string) (string, error) {
				toolExecuted = true
				receivedArgs = args
				return "8", nil
			},
		},
	}

	result, err := client.CompleteWithTools(ctx, msgs, tools)
	assert.NoError(t, err)
	assert.True(t, toolExecuted, "tool was not executed")
	assert.Equal(t, `{"operation": "add", "a": 5, "b": 3}`, receivedArgs)
	assert.Equal(t, "The answer is 8", result)
	assert.Equal(t, 2, callCount)
}

func TestCompleteWithTools_MultipleToolCalls(t *testing.T) {
	callCount := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// First call: return multiple tool calls
		if callCount == 1 {
			w.Write([]byte(chatCompletionResponse("", []map[string]interface{}{
				toolCall("call-1", "tool1", `{"param": "value1"}`),
				toolCall("call-2", "tool2", `{"param": "value2"}`),
			})))
			return
		}

		// Second call: return final response
		w.Write([]byte(chatCompletionResponse("all tools executed", nil)))
	}

	client := testClient(t, handler)
	ctx := context.Background()
	msgs := testMessages()

	tool1Executed := false
	tool2Executed := false
	tools := []LLMTool{
		{
			Name: "tool1",
			Function: func(args string) (string, error) {
				tool1Executed = true
				return "result1", nil
			},
		},
		{
			Name: "tool2",
			Function: func(args string) (string, error) {
				tool2Executed = true
				return "result2", nil
			},
		},
	}

	result, err := client.CompleteWithTools(ctx, msgs, tools)
	assert.NoError(t, err)
	assert.True(t, tool1Executed && tool2Executed, "not all tools were executed")
	assert.Equal(t, "all tools executed", result)
	assert.Equal(t, 2, callCount)
}

func TestCompleteWithTools_InvalidLastMessage(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not make API call with invalid message")
	})

	ctx := context.Background()
	msgs := []LLMMessage{
		{
			Role:    constants.LLMClientMessageAssistant,
			Content: "not a user message",
		},
	}

	_, err := client.CompleteWithTools(ctx, msgs, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "last message must be user")
}

func TestValidateOpenrouterReasoningEffort(t *testing.T) {
	// Valid efforts should not return an error
	validEfforts := []string{"none", "minimal", "low", "medium", "high"}
	for _, effort := range validEfforts {
		err := validateOpenrouterReasoningEffort(effort)
		assert.NoError(t, err, "expected no error for valid effort %q", effort)
	}

	// Invalid effort should return an error
	err := validateOpenrouterReasoningEffort("invalid_effort")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid effort")
}
