// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
	"bytes"
	"fmt"
	"net/url"
	"regexp"
)

// TagAttribute represents a tag and its source attribute that needs URL processing
type TagAttribute struct {
	Tag       string
	Attribute string
}

// DefaultTagAttributes returns the default set of HTML tags and their attributes
// that should have their URLs made relative
func DefaultTagAttributes() []TagAttribute {
	return []TagAttribute{
		{Tag: "img", Attribute: "src"},
		{Tag: "script", Attribute: "src"},
		{Tag: "form", Attribute: "action"},
		{Tag: "frame", Attribute: "src"},
		{Tag: "frame", Attribute: "longdesc"},
		{Tag: "input", Attribute: "src"},
		{Tag: "object", Attribute: "data"},
		{Tag: "object", Attribute: "codebase"},
		{Tag: "audio", Attribute: "src"},
		{Tag: "object", Attribute: "codebase"},
		{Tag: "image", Attribute: "href"},
		{Tag: "object", Attribute: "codebase"},
		{Tag: "link", Attribute: "href"},
		{Tag: "button", Attribute: "formaction"},
		{Tag: "embed", Attribute: "src"},
	}
}

// MakeURLsRelative takes HTML content and makes URLs relative for specified tag attributes,
// but only for URLs matching the specified host/ip.
// It returns the modified HTML content and any error encountered.
func MakeURLsRelative(content []byte, tagAttrs []TagAttribute, targetHost string) ([]byte, error) {
	result := content

	// Process each tag-attribute pair
	for _, ta := range tagAttrs {
		// Create regex pattern for the current tag-attribute
		// This matches both single and double quoted attribute values
		pattern := regexp.MustCompile(`<` + ta.Tag + `[^>]+` + ta.Attribute + `=['"]([^'"]+)['"]`)

		// Find all matches and process them
		matches := pattern.FindAllSubmatch(result, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			originalURL := match[1]
			relativeURL, err := makeURLRelative(originalURL, targetHost)
			if err != nil {
				// Skip this URL if there's an error parsing it
				continue
			}

			// Only replace if we got a different URL back
			if !bytes.Equal(originalURL, relativeURL) {
				// Replace the original URL with the relative one
				originalAttr := []byte(ta.Attribute + `="` + string(originalURL) + `"`)
				newAttr := []byte(ta.Attribute + `="` + string(relativeURL) + `"`)
				result = bytes.Replace(result, originalAttr, newAttr, 1)

				// Also handle single quotes
				originalAttr = []byte(ta.Attribute + `='` + string(originalURL) + `'`)
				newAttr = []byte(ta.Attribute + `='` + string(relativeURL) + `'`)
				result = bytes.Replace(result, originalAttr, newAttr, 1)
			}
		}
	}

	return result, nil
}

// makeURLRelative converts an absolute URL to a relative one by removing the scheme and host,
// but only if the URL's host matches the target host/ip
func makeURLRelative(urlBytes []byte, targetHost string) ([]byte, error) {
	// Parse the URL
	u, err := url.Parse(string(urlBytes))
	if err != nil {
		return urlBytes, fmt.Errorf("error parsing URL: %w", err)
	}

	// If URL has no host or is already relative, return as is
	if !u.IsAbs() || u.Host == "" {
		return urlBytes, nil
	}

	// Check if the host matches our target IP
	if u.Host != targetHost {
		return urlBytes, nil
	}

	// Get the path, ensuring it starts with /
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		path += "#" + u.Fragment
	}

	return []byte(path), nil
}
