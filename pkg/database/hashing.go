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
		"checksum":      true,
		"credential":    true,
		"credentials":   true,
		"creds":         true,
		"csrf":          true,
		"csrf-token":    true,
		"csrftoken":     true,
		"digest":        true,
		"e-mail":        true,
		"e_mail":        true,
		"email":         true,
		"email-address": true,
		"hash":          true,
		"id":            true,
		"identity":      true,
		"key":           true,
		"log":           true,
		"login":         true,
		"mail":          true,
		"new-login":     true,
		"new-pass":      true,
		"new-passwd":    true,
		"new-password":  true,
		"new-user":      true,
		"new-username":  true,
		"new_login":     true,
		"new_pass":      true,
		"new_passwd":    true,
		"new_password":  true,
		"new_user":      true,
		"newlogin":      true,
		"newuser":       true,
		"newusername":   true,
		"pass":          true,
		"passwd":        true,
		"password":      true,
		"pwd":           true,
		"redirect":      true,
		"redirect-to":   true,
		"secret":        true,
		"secretkey":     true,
		"sess":          true,
		"session":       true,
		"session-id":    true,
		"user":          true,
		"uname":         true,
		"user_name":     true,
		"username":      true,
		"xsrf":          true,
		"xsrf-token":    true,
		"xsrftoken":     true,
	}

	// Form fields.
	if req.ContentType == "application/x-www-form-urlencoded" {
		var formFields []string

		parsedQuery, err := util.CustomParseQuery(string(req.Body))
		// We accept that an error can occur here because payloads are often really
		// a mess and don't always parse well. If an error occurs; we don't return.
		if err == nil {
			for paramName, value := range parsedQuery {
				lowerParamname := strings.ToLower(paramName)
				formFields = append(formFields, lowerParamname)
				if _, ok := parameterValsToIgnore[lowerParamname]; !ok {
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
		lowerParamName := strings.ToLower(paramName)
		queryFields = append(queryFields, lowerParamName)
		if _, ok := parameterValsToIgnore[lowerParamName]; !ok {
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
