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
	"lophiid/pkg/util/constants"
	"lophiid/pkg/util/decoding"
	"regexp"
	"strconv"
)

var (
	devTCPIPv4Reg = regexp.MustCompile(`/dev/tcp/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/([\d]+)`)
	devTCPIPv6Reg = regexp.MustCompile(`/dev/tcp/([0-9a-fA-F:]+)/([\d]+)`)
	devTCPHostReg = regexp.MustCompile(`/dev/tcp/([0-9a-zA-Z\-\.]+\.[a-zA-Z]{2,})/([\d]+)`)
)

// TCPExtractor extracts IP/hostnames and port combinations from
// /dev/tcp/ip/port addresses.
type TCPExtractor struct {
	result   map[string]int
	metaType string
}

func NewTCPExtractor(result map[string]int) *TCPExtractor {
	return &TCPExtractor{
		result:   result,
		metaType: constants.ExtractorTypeTcpLink,
	}
}

func (u *TCPExtractor) MetaType() string {
	return u.metaType
}

func (u *TCPExtractor) ParseRequest(req *models.Request) {
	for _, s := range decoding.StringsFromRequest(req) {
		u.ParseString(s)
	}
}

func (u *TCPExtractor) ParseString(s string) {
	ipv4Matches := devTCPIPv4Reg.FindAllStringSubmatch(s, -1)
	ipv6sMatches := devTCPIPv6Reg.FindAllStringSubmatch(s, -1)
	hostMatches := devTCPHostReg.FindAllStringSubmatch(s, -1)

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

func (u *TCPExtractor) GetMetadatas(requestID int64) []models.RequestMetadata {
	mds := make([]models.RequestMetadata, 0, len(u.result))
	for k, v := range u.result {
		mds = append(mds, models.RequestMetadata{
			Type:      u.MetaType(),
			Data:      fmt.Sprintf("/dev/tcp/%s/%d", k, v),
			RequestID: requestID,
		})
	}

	return mds
}
