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
	"lophiid/pkg/database"
	"lophiid/pkg/util/decoding"
	"regexp"
	"strconv"
)

var (
	ncIPv4Reg = regexp.MustCompile(`nc\s+(?:\-4\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\d]+)`)
	ncIPv6Reg = regexp.MustCompile(`nc\s+(?:\-6\s+)?([0-9a-fA-F:]+)\s+([\d]+)`)
	ncHostReg = regexp.MustCompile(`nc\s+(?:\-[46]{1}\s)?([0-9a-zA-Z\-\.]+\.[a-zA-Z]{2,})\s+([\d]+)`)
)

type NCExtractor struct {
	result   map[string]int
	metaType string
}

func NewNCExtractor(result map[string]int) *NCExtractor {
	return &NCExtractor{
		result:   result,
		metaType: "PAYLOAD_NETCAT",
	}
}

func (u *NCExtractor) MetaType() string {
	return u.metaType
}

func (u *NCExtractor) ParseRequest(req *database.Request) {
	for _, s := range decoding.StringsFromRequest(req) {
		u.ParseString(s)
	}
}

func (u *NCExtractor) ParseString(s string) {
	ipv4Matches := ncIPv4Reg.FindAllStringSubmatch(s, -1)
	ipv6sMatches := ncIPv6Reg.FindAllStringSubmatch(s, -1)
	hostMatches := ncHostReg.FindAllStringSubmatch(s, -1)

	for _, matches := range append(append(ipv6sMatches, hostMatches...), ipv4Matches...) {
		address := matches[1]
		port := matches[2]

		intPort, err := strconv.Atoi(port)
		if err != nil {
			slog.Warn("unable to parse port", slog.String("port", port), slog.String("error", err.Error()))
		}

		u.result[address] = intPort
	}
}

func (u *NCExtractor) GetMetadatas(requestID int64) []database.RequestMetadata {
	mds := []database.RequestMetadata{}
	for k, v := range u.result {
		mds = append(mds, database.RequestMetadata{
			Type:      u.MetaType(),
			Data:      fmt.Sprintf("%s %d", k, v),
			RequestID: requestID,
		})
	}

	return mds
}
