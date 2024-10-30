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

import "strings"

func SplitCommandsOnSemi(commands string) []string {

	ret := []string{}
	stringStart := 0
	inQuote := false
	var inQuoteType byte
	for idx := 0; idx < len(commands); idx += 1 {
		chr := commands[idx]

		if chr == '\\' {
			idx += 1
			continue
		}

		if chr == '\'' || chr == '"' {
			if !inQuote {
				inQuoteType = chr
				inQuote = true
			} else if chr == inQuoteType {
				inQuote = false
			}
			continue
		}

		if inQuote {
			continue
		}

		if chr == ';' {
			cmd := strings.TrimSpace(commands[stringStart:idx])
			if cmd != "" {
				ret = append(ret, cmd)
			}
			stringStart = idx + 1
		}
	}

	cmd := strings.TrimSpace(commands[stringStart:])
	if cmd != "" {
		ret = append(ret, cmd)
	}
	return ret
}
