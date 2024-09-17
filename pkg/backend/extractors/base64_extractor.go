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
	"encoding/base64"
	"lophiid/pkg/database"
	"lophiid/pkg/util"
	"regexp"
	"strings"
)

var base64Reg = regexp.MustCompile(`([a-zA-Z0-9=/+]*)`)

type Base64Extractor struct {
	result        map[string][]byte
	asciiOnly     bool
	metaType      string
	subExtractors []Extractor
}

func NewBase64Extractor(result map[string][]byte, asciiOnly bool) *Base64Extractor {
	return &Base64Extractor{
		result:    result,
		asciiOnly: asciiOnly,
		metaType:  "DECODED_STRING_BASE64",
	}
}

func (b *Base64Extractor) MetaType() string {
	return b.metaType
}

func (b *Base64Extractor) ParseRequest(req *database.Request) {
	for _, v := range StringsFromRequest(req) {
		b.FindAndAdd(v)
	}
}

func (b *Base64Extractor) ParseString(s string) {
	b.FindAndAdd(s)
}

func (b *Base64Extractor) AddSubExtractor(ex Extractor) {
	b.subExtractors = append(b.subExtractors, ex)
}

func (b *Base64Extractor) FindAndAdd(data string) int64 {
	allMatches := base64Reg.FindAllString(data, -1)
	if allMatches == nil {
		return 0
	}

	for _, v := range allMatches {
		// Check if there is padding. If so, remove anything that might be there
		// after the padding.
		pIdx := strings.Index(v, "==")
		if pIdx == -1 {
			pIdx = strings.Index(v, "=")
			if pIdx != -1 {
				v = v[0 : pIdx+1]
			}
		} else {
			v = v[0 : pIdx+2]
		}
		// Base64 string are always a multiple length of 4
		sLen := len(v)
		if sLen == 0 || sLen < 4 {
			continue
		}

		quo := sLen % 4
		if quo != 0 {
			if (sLen-quo) >= 4 && v[sLen-1:] == "=" {
				// Give it a final shot when the string ends with padding. We strip the
				// first characters until the string can decode.
				v = v[quo:]
			} else {
				continue
			}
		}

		decoded, err := base64.StdEncoding.DecodeString(v)
		if err == nil {
			// Finally check if the string is ascii or not.
			if !b.asciiOnly || util.IsStringASCII(string(decoded)) {
				b.result[v] = decoded

				for _, ex := range b.subExtractors {
					ex.ParseString(string(decoded))
				}
			}
		}
	}
	return int64(len(b.result))
}

func (u *Base64Extractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for _, v := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      string(v),
			RequestID: requestID,
		})
	}

	return mds
}
