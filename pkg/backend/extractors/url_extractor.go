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
	"lophiid/pkg/database"
	"lophiid/pkg/util/constants"
	"regexp"
	"strings"

	"mvdan.cc/xurls/v2"
)

var (
	// Yes. These are not the best.. now I do prefer the regexes to be somewhat
	// readable and additionally I also prefer them to rather match to broadly
	// then to miss out potential matches. However I recognize that these can be
	// improved and I'd be happy if you send me better ones ;p
	urlStrictReg = xurls.Strict()
	urlIPReg     = regexp.MustCompile(`[\s\t]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:[\d]+)?/[a-zA-Z0-9_\-\./\?&:=]*`)
)

func ExtractUrls(data string) []string {
	// Add regexes for URLs that have no scheme. Specifically also for commands
	// like curl 1.1.1.1/sh

	ip := urlIPReg.FindAllString(data, -1)
	sc := urlStrictReg.FindAllString(data, -1)

	retmap := make(map[string]bool)
	var ret []string
	for _, entry := range append(ip, sc...) {
		if strings.Contains(entry, ";") {
			parts := strings.Split(entry, ";")
			entry = parts[0]
		}
		if strings.Contains(entry, "+") {
			parts := strings.Split(entry, "+")
			entry = parts[0]
		}
		centry := strings.TrimSpace(entry)
		if _, ok := retmap[centry]; !ok {
			retmap[centry] = true
			ret = append(ret, centry)
		}
	}
	return ret
}

type URLExtractor struct {
	result   map[string]struct{}
	metaType string
}

func NewURLExtractor(result map[string]struct{}) *URLExtractor {
	return &URLExtractor{
		result:   result,
		metaType: constants.ExtractorTypeLink,
	}
}

func (u *URLExtractor) MetaType() string {
	return u.metaType
}

func (u *URLExtractor) ParseRequest(req *database.Request) {
	var member struct{}
	for _, s := range StringsFromRequest(req) {
		for _, url := range ExtractUrls(s) {
			// Skip the URL if it contains our honeypot IP.
			if !strings.Contains(url, req.HoneypotIP) {
				u.result[url] = member
			}
		}
	}
}

func (u *URLExtractor) ParseString(s string) {
	var member struct{}
	for _, url := range ExtractUrls(s) {
		u.result[url] = member
	}
}

func (u *URLExtractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for result := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      result,
			RequestID: requestID,
		})
	}

	return mds
}
