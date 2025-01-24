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
//
package backend

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

//		ipBasedUrl, ip, hostHeader, err := ConvertURLToIPBased(v)

// Test ConvertURLToIPBased
func TestConvertURLToIPBased(t *testing.T) {

	for _, test := range []struct {
		description        string
		url                string
		expectedUrl        string
		expectedIP         string
		expectedHostHeader string
		expectedErr        error
	}{
		{
			description:        "simple url, no explicit port",
			url:                "http://example.org",
			expectedUrl:        "http://1.1.1.1:80",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org",
			expectedErr:        nil,
		},
		{
			description:        "simple url, no explicit port, ssl",
			url:                "https://example.org",
			expectedUrl:        "https://1.1.1.1:443",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org",
			expectedErr:        nil,
		},
		{
			description:        "simple url, explicit port",
			url:                "https://example.org:8888/aaa",
			expectedUrl:        "https://1.1.1.1:8888/aaa",
			expectedIP:         "1.1.1.1",
			expectedHostHeader: "example.org:8888",
			expectedErr:        nil,
		},
		{
			description:        "simple url, explicit port, ipv6",
			url:                "https://example.org:8888/aaa",
			expectedUrl:        "https://[2a00:1450:400a:800::2004]:8888/aaa",
			expectedIP:         "2a00:1450:400a:800::2004",
			expectedHostHeader: "example.org:8888",
			expectedErr:        nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			ipUrl, ip, hostHeader, err := ConvertURLToIPBasedImpl(test.url, func(ip string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(test.expectedIP)}, nil
			})

			assert.Equal(t, test.expectedUrl, ipUrl, "URL mismatch")
			assert.Equal(t, test.expectedIP, ip, "IP mismatch")
			assert.Equal(t, test.expectedHostHeader, hostHeader, "Host header mismatch")
			assert.Equal(t, test.expectedErr, err, "Error mismatch")
		})
	}

}
