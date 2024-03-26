package database

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// GetHashFromStaticRequestFields calculates a hash based on HTTP request fields
// that are considered static. Examples are header, parameter names but not
// parameter values.
func GetHashFromStaticRequestFields(rawRequest string) (string, error) {

	hash := sha256.New()

	sReader := strings.NewReader(rawRequest)
	newReq, err := http.ReadRequest(bufio.NewReader(sReader))
	if err != nil {
		return "", err
	}

	hash.Write([]byte(newReq.Method))
	hash.Write([]byte(newReq.URL.Path))

	// Add the headers.
	var headerFields []string
	for headerName := range newReq.Header {
		headerFields = append(headerFields, headerName)
	}

	sort.Strings(headerFields)
	for _, field := range headerFields {
		hash.Write([]byte(field))
	}

	// Form fields.
	if newReq.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if err := newReq.ParseForm(); err == nil {
			var formFields []string
			for formKey := range newReq.PostForm {
				formFields = append(formFields, formKey)
			}
			sort.Strings(formFields)
			for _, field := range formFields {
				hash.Write([]byte(field))
			}
		}
	}

	// Query fields.
	parsedQuery, err := url.ParseQuery(newReq.URL.RawQuery)
	if err != nil {
		return "", err
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
