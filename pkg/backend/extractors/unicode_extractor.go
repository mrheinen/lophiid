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
package extractors

import (
	"fmt"
	"log/slog"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/util/decoding"
	"regexp"
	"strconv"
	"strings"
)

var unicodeRegex = regexp.MustCompile(`((?:\\u[0-9a-fA-F]{4})+)`)

type UnicodeExtractor struct {
	result        map[string]string
	asciiOnly     bool
	metaType      string
	subExtractors []Extractor
}

func NewUnicodeExtractor(result map[string]string, asciiOnly bool) *UnicodeExtractor {
	return &UnicodeExtractor{
		result:    result,
		asciiOnly: asciiOnly,
		metaType:  constants.ExtractorTypeUnicode,
	}
}

func (b *UnicodeExtractor) MetaType() string {
	return b.metaType
}

func (b *UnicodeExtractor) ParseRequest(req *models.Request) {
	for _, v := range decoding.StringsFromRequest(req) {
		b.FindAndAdd(v)
	}
}

func (b *UnicodeExtractor) ParseString(s string) {
	b.FindAndAdd(s)
}

func (b *UnicodeExtractor) AddSubExtractor(ex Extractor) {
	b.subExtractors = append(b.subExtractors, ex)
}

func unescapeUnicode(input string) (string, error) {
	var result strings.Builder
	i := 0
	for i < len(input) {
		if i+5 < len(input) && input[i:i+2] == "\\u" {
			r, err := strconv.ParseInt(input[i+2:i+6], 16, 32)
			if err != nil {
				return "", fmt.Errorf("invalid Unicode escape sequence at position %d: %v", i, err)
			}
			result.WriteRune(rune(r))
			i += 6
		} else {
			result.WriteByte(input[i])
			i++
		}
	}
	return result.String(), nil
}

func (b *UnicodeExtractor) FindAndAdd(data string) int64 {
	allMatches := unicodeRegex.FindAllString(data, -1)
	if allMatches == nil {
		return 0
	}

	for _, v := range allMatches {
		res, err := unescapeUnicode(v)
		if err != nil {
			slog.Error("unicode decode error", slog.String("input", v), slog.String("error", err.Error()))
		}

		if b.asciiOnly && !util.IsStringASCII(v) {
			continue
		}

		b.result[v] = res
		for _, ex := range b.subExtractors {
			ex.ParseString(string(res))
		}
	}

	return int64(len(b.result))
}

func (u *UnicodeExtractor) GetMetadatas(requestID int64) []models.RequestMetadata {
	mds := make([]models.RequestMetadata, 0, len(u.result))
	for _, v := range u.result {
		mds = append(mds, models.RequestMetadata{
			Type:      u.MetaType(),
			Data:      string(v),
			RequestID: requestID,
		})
	}

	return mds
}
