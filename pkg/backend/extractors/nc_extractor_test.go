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
	"lophiid/pkg/database/models"
	"testing"
)

func TestNCExtractor(t *testing.T) {
	for _, test := range []struct {
		description string
		request     models.Request
		tcpsToFind  map[string]int
	}{
		{
			description: "finds nc command with IPv4",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc 1.1.1.1 8080 aa"),
			},
			tcpsToFind: map[string]int{"1.1.1.1": 8080},
		},
		{
			description: "finds nc command with IPv4 and flag",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc -4 1.1.1.1 8080 aa"),
			},
			tcpsToFind: map[string]int{"1.1.1.1": 8080},
		},
		{
			description: "finds nc command with IPv6",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc 2a00:1450:400a:801::200e 8080 aa"),
			},
			tcpsToFind: map[string]int{"2a00:1450:400a:801::200e": 8080},
		},
		{
			description: "finds nc command with IPv4 and flag",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc -6 2a00:1450:400a:801::200e 8080 aa"),
			},
			tcpsToFind: map[string]int{"2a00:1450:400a:801::200e": 8080},
		},
		{
			description: "finds nc command with hostname",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc example.org 8080 aa"),
			},
			tcpsToFind: map[string]int{"example.org": 8080},
		},
		{
			description: "finds nc command with hostname and flag",
			request: models.Request{
				Uri:  "/",
				Body: []byte("ssadsads nc -6 example.org 8080 aa"),
			},
			tcpsToFind: map[string]int{"example.org": 8080},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			result := make(map[string]int)
			te := NewNCExtractor(result)
			te.ParseRequest(&test.request)

			if len(result) != len(test.tcpsToFind) {
				t.Errorf("expected %d tcp addresses but found %d (%v)", len(test.tcpsToFind), len(result), result)
			}

			mds := te.GetMetadatas(42)
			for k, v := range test.tcpsToFind {
				rv, ok := result[k]
				if !ok {
					t.Errorf("expected to find: %s", k)
					continue
				}

				if rv != v {
					t.Errorf("expected port %d but found %d", v, rv)
				}

				for _, md := range mds {
					expectedM := fmt.Sprintf("%s %d", k, v)
					if md.Data != expectedM {
						t.Errorf("expected: %s, found: %s", expectedM, md.Data)
					}

					if md.Type != "PAYLOAD_NETCAT" {
						t.Errorf("expected PAYLOAD_NETCAT, found %s", md.Type)
					}
				}
			}
		})
	}
}
