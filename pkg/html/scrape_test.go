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
package html

import (
	"lophiid/pkg/util"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractResourceLink(t *testing.T) {
	for _, test := range []struct {
		description  string
		baseUrl      string
		html         string
		expectedUrls []string
	}{
		{
			description:  "gets url",
			baseUrl:      "http://example.org",
			html:         "<html><script src=\"/foo.js\"></html>",
			expectedUrls: []string{"http://example.org/foo.js"},
		},
		{
			description:  "gets multiple urls",
			baseUrl:      "http://example.org",
			html:         "<html><script src=\"/foo.js\"></script><script src=\"http://example.org/aa\"></script></html>",
			expectedUrls: []string{"http://example.org/foo.js", "http://example.org/aa"},
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			urls := ExtractResourceLinks(test.baseUrl, test.html)

			if !util.AreSlicesEqual(urls, test.expectedUrls) {
				t.Errorf("expected %+v, got %+v", test.expectedUrls, urls)
			}

		})
	}
}

func TestNormalizeLink(t *testing.T) {
	for _, test := range []struct {
		description         string
		inputUrl            string
		baseUrl             string
		outputUrl           string
		expectError         bool
		expectErrorContains string
	}{
		{
			description: "absolute url ok",
			inputUrl:    "http://example.org",
			baseUrl:     "http://example.org",
			outputUrl:   "http://example.org",
			expectError: false,
		},
		{
			description: "absolute url ok (https)",
			inputUrl:    "https://example.org",
			baseUrl:     "https://example.org",
			outputUrl:   "https://example.org",
			expectError: false,
		},
		{
			description: "relative url ok, no /",
			inputUrl:    "aa",
			baseUrl:     "http://example.org",
			outputUrl:   "http://example.org/aa",
			expectError: false,
		},
		{
			description: "relative url from file ",
			inputUrl:    "aa",
			baseUrl:     "http://example.org/index.html",
			outputUrl:   "http://example.org/aa",
			expectError: false,
		},
		{
			description: "absolute url, no scheme ok",
			inputUrl:    "//example.org",
			baseUrl:     "http://example.org",
			outputUrl:   "http://example.org",
			expectError: false,
		},
		{
			description: "relative url, just a / with #tag",
			inputUrl:    "/#foo",
			baseUrl:     "http://example.org",
			outputUrl:   "http://example.org/",
			expectError: false,
		},
		{
			description: "relative url, just a / in a subdir",
			inputUrl:    "/foo/bar",
			baseUrl:     "http://example.org/hello/",
			outputUrl:   "http://example.org/foo/bar",
			expectError: false,
		},
		{
			description: "relative url, just a / in a subdir and port",
			inputUrl:    "/foo/bar",
			baseUrl:     "http://example.org:8888/hello/",
			outputUrl:   "http://example.org:8888/foo/bar",
			expectError: false,
		},
		{
			description:         "wrong scheme",
			inputUrl:            "mailto:me@me.me",
			baseUrl:             "http://example.org",
			outputUrl:           "",
			expectError:         true,
			expectErrorContains: "invalid scheme",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			resultUrl, err := normalizeLink(test.baseUrl, test.inputUrl)

			if test.expectError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Contains(t, err.Error(), test.expectErrorContains, "Error message does not contain expected text")
			} else {
				assert.NoError(t, err, "Got unexpected error")
			}

			assert.Equal(t, test.outputUrl, resultUrl, "Normalized URL does not match expected")
		})
	}
}
