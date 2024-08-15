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
package database

import (
	"crypto/sha256"
	"fmt"
	"lophiid/pkg/util"
	"sort"
	"strings"
)

// GetHashFromStaticRequestFields calculates a hash based on HTTP request fields
// that are considered static. Examples are header, parameter names but not
// parameter values.
func GetHashFromStaticRequestFields(req *Request) (string, error) {

	hash := sha256.New()

	hash.Write([]byte(req.Method))
	hash.Write([]byte(req.Path))

	// Add the headers.
	var headerFields []string
	for _, header := range req.Headers {
		headerArray := strings.SplitN(header, ": ", 2)
		headerFields = append(headerFields, headerArray[0])
	}

	sort.Strings(headerFields)
	for _, field := range headerFields {
		hash.Write([]byte(field))
	}

	// Form fields.
	if req.ContentType == "application/x-www-form-urlencoded" {
		var formFields []string

		parsedQuery, err := util.CustomParseQuery(string(req.Body))
		// We accept that an error can occur here because payloads are often really
		// a mess and don't always parse well. If an error occurs; we don't return.
		if err == nil {
			for paramName := range parsedQuery {
				formFields = append(formFields, paramName)
			}

			sort.Strings(formFields)
			for _, field := range formFields {
				hash.Write([]byte(field))
			}
		}
	}

	// Query fields.
	parsedQuery, err := util.CustomParseQuery(req.Query)
	if err != nil {
		return "", fmt.Errorf("failed to parse query: %w", err) //nolint:err
	}

	var queryFields []string
	for paramName := range parsedQuery {
		queryFields = append(queryFields, paramName)
	}

	sort.Strings(queryFields)
	for _, field := range queryFields {
		hash.Write([]byte(field))
	}
	sum := hash.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}
