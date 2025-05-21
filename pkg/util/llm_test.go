package util

import (
	"testing"
)

func TestRemoveThinkingFromResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with thinking section",
			input:    "I'm thinking about this...\n</think>\nHere is the actual response",
			expected: "Here is the actual response",
		},
		{
			name:     "without thinking section",
			input:    "Just a normal response with no thinking tags",
			expected: "Just a normal response with no thinking tags",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only thinking section",
			input:    "Some thinking content</think>",
			expected: "",
		},
		{
			name:     "multiple thinking tags",
			input:    "First thinking</think> Response with </think> mentioned again",
			expected: "Response with </think> mentioned again",
		},
		{
			name:     "with whitespace after tag",
			input:    "Thinking process</think>  \n  Actual response",
			expected: "Actual response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveThinkingFromResponse(tt.input)
			if result != tt.expected {
				t.Errorf("RemoveThinkingFromResponse() = %q, want %q", result, tt.expected)
			}
		})
	}
}
