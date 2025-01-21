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
	"fmt"
	"log/slog"
	"lophiid/pkg/util"
	"strconv"
	"strings"
)

func returnExpansionToCharsetMap() map[string]string {
	return map[string]string{
		"A-Z": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"a-z": "abcdefghijklmnopqrstuvwxyz",
		"0-9": "0123456789",
		"A-F": "ABCDEF",
		"a-f": "abcdef",
	}
}

// ParseCharacterSet parses a string pattern in the format %%STRING%%pattern%%length%%
// and returns the individual character set components and the length.
// For example, %%STRING%%A-Za-z0-9_\-%%32%% returns ([]string{"A-Z", "a-z", "0-9", "_", "-"}, 32)
func ParseCharacterSetTag(pattern string) ([]string, int) {
	const prefix = "%%STRING%%"
	const midfix = "%%"
	const suffix = "%%"

	// Check basic format
	if !strings.HasPrefix(pattern, prefix) {
		slog.Error("invalid pattern", slog.String("pattern", pattern))
		return nil, 0
	}

	// Find the position of the length marker
	parts := strings.Split(pattern[len(prefix):], midfix)
	if len(parts) != 3 || parts[2] != "" {
		slog.Error("invalid pattern", slog.String("pattern", pattern))
		return nil, 0
	}

	content := parts[0]
	lengthStr := parts[1]

	// Parse the length
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		slog.Error("invalid length", slog.String("length", lengthStr), slog.String("pattern", pattern))
		return nil, 0
	}

	// Handle escaped characters
	content = strings.ReplaceAll(content, "\\-", "-")

	var result []string
	i := 0
	for i < len(content) {
		if i+2 < len(content) && content[i+1] == '-' {
			// Handle ranges like A-Z, a-z, 0-9
			result = append(result, content[i:i+3])
			i += 3
		} else {
			// Handle single characters like _ or -
			result = append(result, string(content[i]))
			i++
		}
	}

	return result, length
}

func GenerateRandomString(charsets []string, length int) (string, error) {
	if len(charsets) == 0 {
		return "", fmt.Errorf("no charsets provided")
	}

	charsetMap := returnExpansionToCharsetMap()
	allChars := ""

	for _, csn := range charsets {
		if csn == "" {
			return "", fmt.Errorf("empty charset provided")
		}
		chars, ok := charsetMap[csn]
		if !ok {
			allChars += csn
		} else {
			allChars += chars
		}
	}

	if allChars == "" {
		return "", fmt.Errorf("no valid characters in charsets")
	}

	return util.GenerateRandomString(length, allChars), nil
}
