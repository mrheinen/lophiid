package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPingExtractor_ParseString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]int
	}{
		{
			name:     "IPv4 ping command",
			input:    "ping -c 5 192.168.1.1",
			expected: map[string]int{"192.168.1.1": 5},
		},
		{
			name:     "IPv6 ping command",
			input:    "ping6 -c 3 2001:db8::1",
			expected: map[string]int{"2001:db8::1": 3},
		},
		{
			name:     "Hostname ping command",
			input:    "ping -c 4 example.com",
			expected: map[string]int{"example.com": 4},
		},
		{
			name:     "Invalid count",
			input:    "ping -c abc 192.168.1.1",
			expected: map[string]int{},
		},
		{
			name:     "Multiple commands in one string",
			input:    "ping -c 2 192.168.1.1\nping6 -c 3 2001:db8::1\nping -c 4 example.com",
			expected: map[string]int{
				"192.168.1.1":  2,
				"2001:db8::1":  3,
				"example.com":  4,
			},
		},
		{
			name:     "No matches",
			input:    "some random text",
			expected: map[string]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := make(map[string]int)
			extractor := NewPingExtractor(result)
			extractor.ParseString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
