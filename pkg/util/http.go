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
package util

import (
	"strings"
)

// ParseHeaders parses HTTP headers from a raw string into a map.
// It ignores invalid lines or lines that do not look like headers.
// The headers map must be a pointer to a map[string]string.
// If the map is nil, it will be initialized.
func ParseHeaders(raw string, headers *map[string]string) {
	if headers == nil {
		return
	}
	if *headers == nil {
		*headers = make(map[string]string)
	}

	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for the first colon
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			// Not a valid header line (gibberish or incomplete)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" {
			// Key cannot be empty
			continue
		}

		(*headers)[key] = value
	}
}
