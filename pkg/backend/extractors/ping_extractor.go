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
	"lophiid/pkg/util/decoding"
	"regexp"
	"strconv"
)

var (
	simplePingIPv4Reg = regexp.MustCompile(`ping?\s+\-c\s*([\d+])\s+([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})`)
	simplePingIPv6Reg = regexp.MustCompile(`ping6\s+\-c\s*([\d+])\s+([0-9a-fA-F:]+)`)
	simplePingHostReg = regexp.MustCompile(`ping6?\s+\-c\s*([\d+])\s+([0-9a-zA-Z\-\.]+\.[a-zA-Z]{2,})`)
)

type PingExtractor struct {
	result   map[string]int
	metaType string
}

func NewPingExtractor(result map[string]int) *PingExtractor {
	return &PingExtractor{
		result:   result,
		metaType: "PAYLOAD_PING",
	}
}

func (u *PingExtractor) MetaType() string {
	return u.metaType
}

func (u *PingExtractor) ParseRequest(req *models.Request) {
	for _, s := range decoding.StringsFromRequest(req) {
		u.ParseString(s)
	}
}

func (u *PingExtractor) ParseString(s string) {
	ipv4Matches := simplePingIPv4Reg.FindAllStringSubmatch(s, -1)
	ipv6Matches := simplePingIPv6Reg.FindAllStringSubmatch(s, -1)
	hostMatches := simplePingHostReg.FindAllStringSubmatch(s, -1)

	for _, matches := range append(append(ipv4Matches, ipv6Matches...), hostMatches...) {
		count := matches[1]
		address := matches[2]

		intCount, err := strconv.Atoi(count)
		if err != nil {
			slog.Warn("unable to parse count", slog.String("count", count), slog.String("error", err.Error()))
			continue
		}

		u.result[address] = intCount
	}
}

func (u *PingExtractor) GetMetadatas(requestID int64) []models.RequestMetadata {
	mds := make([]models.RequestMetadata, 0, len(u.result))
	for k, v := range u.result {
		mds = append(mds, models.RequestMetadata{
			Type:      u.MetaType(),
			Data:      fmt.Sprintf("%s %d", k, v),
			RequestID: requestID,
		})
	}

	return mds
}
