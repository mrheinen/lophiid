package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAlertEventKey(t *testing.T) {
	tests := []struct {
		name        string
		eventType   string
		eventSubtype string
		expected    string
	}{
		{
			name:         "simple values",
			eventType:    "SESSION_INFO",
			eventSubtype: "SUCCESSIVE_PAYLOAD",
			expected:     "SESSION_INFO SUCCESSIVE_PAYLOAD",
		},
		{
			name:         "trims leading/trailing spaces",
			eventType:    "  SESSION_INFO  ",
			eventSubtype: "  SUCCESSIVE_PAYLOAD  ",
			expected:     "SESSION_INFO SUCCESSIVE_PAYLOAD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateAlertEventKey(tt.eventType, tt.eventSubtype)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAlertEventConfig(t *testing.T) {
	tests := []struct {
		name        string
		entries     []string
		expected    map[string]bool
		expectError bool
	}{
		{
			name:     "valid single entry",
			entries:  []string{"SESSION_INFO SUCCESSIVE_PAYLOAD"},
			expected: map[string]bool{"SESSION_INFO SUCCESSIVE_PAYLOAD": true},
		},
		{
			name:    "valid multiple entries",
			entries: []string{"SESSION_INFO SUCCESSIVE_PAYLOAD", "RULE DYNAMIC_RULE"},
			expected: map[string]bool{
				"SESSION_INFO SUCCESSIVE_PAYLOAD": true,
				"RULE DYNAMIC_RULE":               true,
			},
		},
		{
			name:     "handles extra whitespace",
			entries:  []string{"  SESSION_INFO   SUCCESSIVE_PAYLOAD  "},
			expected: map[string]bool{"SESSION_INFO SUCCESSIVE_PAYLOAD": true},
		},
		{
			name:     "empty list",
			entries:  []string{},
			expected: map[string]bool{},
		},
		{
			name:        "invalid entry - single word",
			entries:     []string{"SESSION_INFO"},
			expectError: true,
		},
		{
			name:        "invalid entry - too many words",
			entries:     []string{"SESSION_INFO SUCCESSIVE_PAYLOAD EXTRA"},
			expectError: true,
		},
		{
			name:        "invalid entry - empty string",
			entries:     []string{""},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseAlertEventConfig(tt.entries)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
