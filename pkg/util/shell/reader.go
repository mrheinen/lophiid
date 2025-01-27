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
package shell

import (
	"fmt"
	"os"
)

type Iterator interface {
	Next() (string, bool)
}

type ScriptIterator struct {
	fileData []byte
	index    int
}

func (f *ScriptIterator) FromFile(file string) error {
	if _, err := os.Stat(file); err != nil {
		return fmt.Errorf("file not accessible: %w", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	f.fileData = data
	return nil
}

func (f *ScriptIterator) FromBuffer(buffer []byte) error {
	f.fileData = buffer
	return nil
}


func (f *ScriptIterator) Next() (string, bool) {
	if f.fileData == nil {
		return "", false
	}

	if len(f.fileData) == 0 {
		return "", false
	}

	retString := ""
	inQuote := false
	var quote byte
	i := 0

	for ; i < len(f.fileData); i++ {
		ch := f.fileData[i]

		// Skip through content in quotes
		if ch == '\'' || ch == '"' {
			if inQuote {
				if ch == quote {
					inQuote = false
				}
				continue
			} else {
				inQuote = true
				quote = ch
				continue
			}
		}

		if ch == '\n' {
			retString = string(f.fileData[:i])
			f.fileData = f.fileData[i+1:]
			return retString, true
		}

		if ch == ';' && !inQuote {
			retString = string(f.fileData[:i])
			f.fileData = f.fileData[i+1:]
			return retString, true
		}
	}

	// Handle the last line (when no newline at the end)
	retString = string(f.fileData)
	f.fileData = nil // Mark as done
	return retString, false
}
