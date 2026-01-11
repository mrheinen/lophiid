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
	"net/netip"
	"net/url"
	"strings"
)

// CustomParseQuery is a wrapper around url.ParseQuery that can handle semicolons in query params
func CustomParseQuery(query string) (url.Values, error) {
	ret, err := url.ParseQuery(query)
	if err != nil && strings.Contains(err.Error(), "semicolon") {
		query = strings.ReplaceAll(query, ";", "%3B")
		return url.ParseQuery(query)
	}

	return ret, err
}

// Get24Network takes an IP string and returns the /24 network address.
func Get24NetworkString(ipAddr string) (string, error) {
	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return "", err
	}

	prefix := netip.PrefixFrom(addr, 24)

	// Masked() returns the network address (zeroing out the host bits)
	return prefix.Masked().Addr().String() + "/24", nil
}
