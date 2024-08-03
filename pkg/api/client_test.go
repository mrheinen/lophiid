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
package api

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func TestGenericClientSegment(t *testing.T) {
	for _, test := range []struct {
		description             string
		response                string
		amountOfResultsExpected int
		expectError             bool
	}{
		{
			description:             "runs ok",
			response:                `{"status":"OK","message":"","data":[ {"id":153} ]}`,
			amountOfResultsExpected: 1,
			expectError:             false,
		},
		{
			description:             "runs into error",
			response:                `{"status":"ERR","message":"","data": null}`,
			amountOfResultsExpected: 0,
			expectError:             true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			client := NewTestClient(func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewBufferString(test.response)),
				}
			})

			apiClient := NewContentApiClient(client, "http://localhost", "AAAA")

			result, err := apiClient.GetDatamodelSegment("", 0, 24)
			if test.expectError != (err != nil) {
				t.Errorf("unexpected error %s", err)
			}

			if len(result) != test.amountOfResultsExpected {
				t.Errorf("expected 1 result, got %d", len(result))
			}
		})
	}
}
