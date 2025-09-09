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
package database

import (
	"crypto/sha256"
	"fmt"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"sort"
	"strings"
)

// GetHashFromStaticRequestFields calculates a hash based on HTTP request fields
// that are considered static. Examples are header, parameter names but not
// parameter values.
func GetHashFromStaticRequestFields(req *models.Request) (string, error) {

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

// GetSameRequestHash returns a hash that aims to be able to be equal for the
// same request against different hosts. It is must more specific than the one
// created above.
func GetSameRequestHash(req *models.Request) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(req.Method))
	hash.Write([]byte(req.Path))

	// Add the headers.
	var headerFields []string
	for _, header := range req.Headers {
		headerArray := strings.SplitN(header, ": ", 2)
		headerFields = append(headerFields, headerArray[0])

		if len(headerArray) == 2 {
			if strings.ToLower(headerArray[0]) == "host" || strings.ToLower(headerArray[0]) == "user-agent" || strings.ToLower(headerArray[0]) == "referer" {
				continue
			}

			if strings.ToLower(headerArray[0]) == "authorization" {
				authArray := strings.SplitN(headerArray[1], " ", 2)
				if len(authArray) == 2 {
					// Just append the BASIC / NTLM / etc keywords
					headerFields = append(headerFields, authArray[0])
				}
			} else {
				headerFields = append(headerFields, headerArray[1])
			}
		}
	}

	sort.Strings(headerFields)
	for _, field := range headerFields {
		hash.Write([]byte(field))
	}

	parameterValsToIgnore := map[string]bool{
		"csrf":          true,
		"csrf-token":    true,
		"csrftoken":     true,
		"xsrf":          true,
		"xsrf-token":    true,
		"xsrftoken":     true,
		"credential":    true,
		"credentials":   true,
		"creds":         true,
		"hash":          true,
		"checksum":      true,
		"user":          true,
		"new-user":      true,
		"new_user":      true,
		"newuser":       true,
		"new-username":  true,
		"newusername":   true,
		"login":         true,
		"newlogin":      true,
		"new-login":     true,
		"new_login":     true,
		"username":      true,
		"user_name":     true,
		"email":         true,
		"email-address": true,
		"e-mail":        true,
		"e_mail":        true,
		"mail":          true,
		"pass":          true,
		"password":      true,
		"new-passwd":    true,
		"new-pass":      true,
		"new-password":  true,
		"new_pass":      true,
		"new_password":  true,
		"new_passwd":    true,
		"passwd":        true,
		"secret":        true,
	}

	// Form fields.
	if req.ContentType == "application/x-www-form-urlencoded" {
		var formFields []string

		parsedQuery, err := util.CustomParseQuery(string(req.Body))
		// We accept that an error can occur here because payloads are often really
		// a mess and don't always parse well. If an error occurs; we don't return.
		if err == nil {
			for paramName, value := range parsedQuery {
				formFields = append(formFields, paramName)
				if _, ok := parameterValsToIgnore[paramName]; !ok {
					formFields = append(formFields, value...)
				}
			}

			sort.Strings(formFields)
			for _, field := range formFields {
				hash.Write([]byte(field))
			}
		}
	} else {
		hash.Write(req.Body)
	}

	// Query fields.
	parsedQuery, err := util.CustomParseQuery(req.Query)
	if err != nil {
		return "", fmt.Errorf("failed to parse query: %w", err) //nolint:err
	}

	var queryFields []string
	for paramName, paramValue := range parsedQuery {
		queryFields = append(queryFields, paramName)
		if _, ok := parameterValsToIgnore[paramName]; !ok {
			queryFields = append(queryFields, paramValue...)
		}
	}

	sort.Strings(queryFields)
	for _, field := range queryFields {
		hash.Write([]byte(field))
	}
	sum := hash.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}
