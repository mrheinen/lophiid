package util

import (
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
