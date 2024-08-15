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
	"lophiid/pkg/database"
	"strings"
	"testing"
	"time"
)

func TestRunQueries(t *testing.T) {
	for _, test := range []struct {
		description            string
		queriesToReturn        []database.StoredQuery
		queriesToReturnError   error
		tagPerQueryReturn      []database.TagPerQuery
		tagPerQueryReturnError error
		returnedErrorContains  string
	}{
		{
			description:            "There are no stored queries",
			queriesToReturn:        []database.StoredQuery{},
			queriesToReturnError:   nil,
			returnedErrorContains:  "",
			tagPerQueryReturn:      []database.TagPerQuery{},
			tagPerQueryReturnError: nil,
		},
		{
			description: "There are stored queries, no query tags though",
			queriesToReturn: []database.StoredQuery{
				{
					ID:    1,
					Query: "uri:/",
				},
				{
					ID:    2,
					Query: "body:boo",
				},
			},
			queriesToReturnError:   nil,
			returnedErrorContains:  "",
			tagPerQueryReturn:      []database.TagPerQuery{},
			tagPerQueryReturnError: nil,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fakeDbClient := database.FakeDatabaseClient{
				QueriesToReturn:        test.queriesToReturn,
				QueriesToReturnError:   test.queriesToReturnError,
				TagPerQueryReturn:      test.tagPerQueryReturn,
				TagPerQueryReturnError: test.tagPerQueryReturnError,
			}

			queryRunner := NewQueryRunnerImpl(&fakeDbClient)

			err := queryRunner.Run(-10 * time.Second)

			if err != nil {
				if test.returnedErrorContains == "" {
					t.Errorf("unexpected error: %s", err.Error())
				} else if !strings.Contains(err.Error(), test.returnedErrorContains) {
					t.Errorf("error did not contain expected string: %s -> %s", test.returnedErrorContains, err.Error())
				}
			} else if test.returnedErrorContains != "" {
				t.Errorf("did not get an error containing: %s", test.returnedErrorContains)
			}
		})
	}
}
