package html

import (
	"strings"
	"testing"
)

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
			if err != nil {
				if test.expectError {
					if !strings.Contains(err.Error(), test.expectErrorContains) {
						t.Errorf("Expected error to contain %s", test.expectErrorContains)
					}
				} else {
					t.Errorf("Unexpected error: %s", err)
				}
			}

			if resultUrl != test.outputUrl {
				t.Errorf("Expected %s, got %s", test.outputUrl, resultUrl)
			}

		})
	}
}
