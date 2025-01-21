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
package templator

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCharacterSetTag(t *testing.T) {
	tests := []struct {
		name           string
		input         string
		wantCharSets  []string
		wantLength    int
		wantNonNil    bool
	}{
		{
			name:          "standard case with multiple ranges",
			input:         "%%STRING%%A-Za-z0-9_\\-%%32%%",
			wantCharSets:  []string{"A-Z", "a-z", "0-9", "_", "-"},
			wantLength:    32,
			wantNonNil:    true,
		},
		{
			name:          "single range with small length",
			input:         "%%STRING%%A-F%%1%%",
			wantCharSets:  []string{"A-F"},
			wantLength:    1,
			wantNonNil:    true,
		},
		{
			name:          "multiple ranges with large length",
			input:         "%%STRING%%a-zA-Z%%999%%",
			wantCharSets:  []string{"a-z", "A-Z"},
			wantLength:    999,
			wantNonNil:    true,
		},
		{
			name:          "single character",
			input:         "%%STRING%%_%%5%%",
			wantCharSets:  []string{"_"},
			wantLength:    5,
			wantNonNil:    true,
		},
		{
			name:          "invalid format - missing prefix",
			input:         "STRING%%A-Z%%32%%",
			wantCharSets:  nil,
			wantLength:    0,
			wantNonNil:    false,
		},
		{
			name:          "invalid format - missing length",
			input:         "%%STRING%%A-Z%%",
			wantCharSets:  nil,
			wantLength:    0,
			wantNonNil:    false,
		},
		{
			name:          "invalid format - non-numeric length",
			input:         "%%STRING%%A-Z%%abc%%",
			wantCharSets:  nil,
			wantLength:    0,
			wantNonNil:    false,
		},
		{
			name:          "escaped hyphen",
			input:         "%%STRING%%\\-%%10%%",
			wantCharSets:  []string{"-"},
			wantLength:    10,
			wantNonNil:    true,
		},
		{
			name:          "mix of ranges and single chars",
			input:         "%%STRING%%A-Z_-%%15%%",
			wantCharSets:  []string{"A-Z", "_", "-"},
			wantLength:    15,
			wantNonNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCharSets, gotLength := ParseCharacterSetTag(tt.input)

			if tt.wantNonNil && gotCharSets == nil {
				t.Error("ParseCharacterSetTag() returned nil, want non-nil")
			}

			if !tt.wantNonNil && gotCharSets != nil {
				t.Error("ParseCharacterSetTag() returned non-nil, want nil")
			}

			if !reflect.DeepEqual(gotCharSets, tt.wantCharSets) {
				t.Errorf("ParseCharacterSetTag() charsets = %v, want %v", gotCharSets, tt.wantCharSets)
			}

			if gotLength != tt.wantLength {
				t.Errorf("ParseCharacterSetTag() length = %v, want %v", gotLength, tt.wantLength)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name        string
		charsets    []string
		length      int
		wantErr     bool
		validateFn  func(string) bool
	}{
		{
			name:     "uppercase only",
			charsets: []string{"A-Z"},
			length:   10,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 10 {
					return false
				}
				for _, c := range s {
					if c < 'A' || c > 'Z' {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "lowercase and numbers",
			charsets: []string{"a-z", "0-9"},
			length:   15,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 15 {
					return false
				}
				for _, c := range s {
					if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "direct characters",
			charsets: []string{"xyz123"},
			length:   8,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 8 {
					return false
				}
				validChars := "xyz123"
				for _, c := range s {
					if !strings.ContainsRune(validChars, c) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "mix of charset and direct characters",
			charsets: []string{"A-Z", "!@#"},
			length:   10,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 10 {
					return false
				}
				for _, c := range s {
					if !((c >= 'A' && c <= 'Z') || strings.ContainsRune("!@#", c)) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "empty charset list",
			charsets: []string{},
			length:   5,
			wantErr:  true,
			validateFn: func(s string) bool {
				return true // Not used since we expect an error
			},
		},
		{
			name:     "empty string in charset",
			charsets: []string{""},
			length:   5,
			wantErr:  true,
			validateFn: func(s string) bool {
				return true // Not used since we expect an error
			},
		},
		{
			name:     "hex characters",
			charsets: []string{"A-F", "0-9"},
			length:   8,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 8 {
					return false
				}
				for _, c := range s {
					if !((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9')) {
						return false
					}
				}
				return true
			},
		},
		{
			name:     "multiple charsets with all types",
			charsets: []string{"A-Z", "a-z", "0-9"},
			length:   20,
			wantErr:  false,
			validateFn: func(s string) bool {
				if len(s) != 20 {
					return false
				}
				for _, c := range s {
					if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
						return false
					}
				}
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRandomString(tt.charsets, tt.length)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if !tt.validateFn(got) {
					t.Errorf("GenerateRandomString() = %v, failed validation", got)
				}

				// Generate another string to ensure randomness
				got2, _ := GenerateRandomString(tt.charsets, tt.length)
				if got == got2 {
					t.Error("GenerateRandomString() generated identical strings in succession")
				}
			}
		})
	}
}
