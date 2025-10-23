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
	"strings"
)

const ThinkingEndTag = "</think>"

// RemoveThinkingFromResponse removes <think>...</think> tags from the content if present.
func RemoveThinkingFromResponse(response string) string {
	endIndex := strings.Index(response, ThinkingEndTag)
	if endIndex == -1 {
		return response
	}

	// Remove everything before and including the </think> tag
	return strings.TrimSpace(response[endIndex+len(ThinkingEndTag):])
}

// RemoveJsonExpression removes ```json...``` tags from the content if present.
func RemoveJsonExpression(response string) string {
	ret := strings.TrimSpace(response)
	ret = strings.TrimPrefix(ret, "```json")
	return strings.TrimSuffix(ret, "```")
}
