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
	"bytes"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
)

type Templator struct {
	stringTagRegex *regexp.Regexp
}

var (
	once          sync.Once
	compiledRegex *regexp.Regexp
)

func NewTemplator() *Templator {
	once.Do(func() {
		var err error
		compiledRegex, err = regexp.Compile(`(%%STRING%%.+%%[0-9]+%%)`)
		if err != nil {
			slog.Error("failed to compile regex", slog.String("error", err.Error()))
			return
		}
	})

	if compiledRegex == nil {
		return nil
	}

	return &Templator{
		stringTagRegex: compiledRegex,
	}
}

func (t *Templator) RenderTemplate(template []byte) ([]byte, error) {
	// extract string tags
	if !bytes.Contains(template, []byte("%%STRING")) {
		slog.Error("no string tags in template")
		return template, nil
	}

	matches := t.stringTagRegex.FindAll(template, -1)
	for _, match := range matches {
		charsets, length := ParseCharacterSetTag(string(match))
		if charsets == nil {
			return nil, fmt.Errorf("invalid string tag: %s", match)
		}

		if length < 1 {
			return nil, fmt.Errorf("invalid length for string tag: %s", match)
		}

		replacementValue, err := GenerateRandomString(charsets, length)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random string: %w", err)
		}

		template = bytes.ReplaceAll(template, match, []byte(replacementValue))
	}

	return template, nil
}
