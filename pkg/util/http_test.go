// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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
package util

import (
	"reflect"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		initial  map[string]string
		expected map[string]string
	}{
		{
			name: "Normal headers",
			raw: `Host: example.com
User-Agent: test-agent
Accept: */*`,
			initial: make(map[string]string),
			expected: map[string]string{
				"Host":       "example.com",
				"User-Agent": "test-agent",
				"Accept":     "*/*",
			},
		},
		{
			name: "With whitespace",
			raw: `  Host  :   example.com  
User-Agent: test-agent  `,
			initial: make(map[string]string),
			expected: map[string]string{
				"Host":       "example.com",
				"User-Agent": "test-agent",
			},
		},
		{
			name:    "Gibberish and empty lines",
			raw:     "Host: example.com\n\nGibberishLineWithoutColon\nAnotherHeader: value",
			initial: make(map[string]string),
			expected: map[string]string{
				"Host":          "example.com",
				"AnotherHeader": "value",
			},
		},
		{
			name:    "Incomplete lines",
			raw:     "Host:\nUser-Agent: test",
			initial: make(map[string]string),
			expected: map[string]string{
				"Host":       "",
				"User-Agent": "test",
			},
		},
		{
			name:    "Nil map initialization",
			raw:     "Host: example.com",
			initial: nil,
			expected: map[string]string{
				"Host": "example.com",
			},
		},
		{
			name:    "Empty input",
			raw:     "",
			initial: make(map[string]string),
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the pointer if it's not nil, effectively simulating passing a variable
			var headers map[string]string
			if tt.initial != nil {
				headers = tt.initial
			}
			// If tt.initial is nil, headers starts as nil (zero value for map)

			ParseHeaders(tt.raw, &headers)

			if !reflect.DeepEqual(headers, tt.expected) {
				t.Errorf("ParseHeaders() = %v, want %v", headers, tt.expected)
			}
		})
	}
}
