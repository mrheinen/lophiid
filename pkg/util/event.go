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
"fmt"
"strings"
)

// GenerateAlertEventKey generates a consistent key for alert events based on
// type and subtype, ensuring consistent formatting without extra spaces.
func GenerateAlertEventKey(eventType, eventSubtype string) string {
	return fmt.Sprintf("%s %s", strings.TrimSpace(eventType), strings.TrimSpace(eventSubtype))
}

// ParseAlertEventConfig parses a list of alert event config entries (format:
// "TYPE SUBTYPE") into a map for efficient lookup. Returns an error if any
// entry does not contain exactly two space-separated parts.
func ParseAlertEventConfig(entries []string) (map[string]bool, error) {
	result := make(map[string]bool)
	for _, entry := range entries {
		parts := strings.Fields(entry)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid alert event config entry %q: expected format 'TYPE SUBTYPE'", entry)
		}
		key := GenerateAlertEventKey(parts[0], parts[1])
		result[key] = true
	}
	return result, nil
}
