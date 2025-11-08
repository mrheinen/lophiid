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
	"fmt"
	"slices"
	"strings"
	"unicode"
)

type WhereType int64

const (
	IS WhereType = iota
	LIKE
	GREATER_THAN
	LOWER_THAN
)

type SearchRequestsParam struct {
	key      string
	value    string
	matching WhereType
	not      bool
}

// ParseQuery parses a query from the UI into an array of SearchRequestParams
// which can than be converted into a SQL query. All query parameters are
// combined in a big AND string. It is possible to perform negative matches
// though by adding a ! before the keyword. For example a negative query would
// be: "!port:80".  The keyword values can be quoted with single or double
// quotes. Quotes should be used when there is a space in the value.
//
// The separator between the keyword and value indicates what kind of matching
// is wanted. The supported separators are:
//
//	:    - match exactly
//	>    - greater than
//	<    - lower than
//	~    - like/contains (use with percentages)
//
// Example queries are below. Note that keywords are dependent on the type of
// data being queried. These examples are for requests data.
//
//	 All POST requests on port 80
//	method:POST port:80
//
//	Any method except POST on ports bigger than 8000 but smaller than 9000
//	!method:POST port>8000 port<9000
//
//	Any GET request with /etc/passwd in the URL
//	method:GET uri~%/etc/passwd%
//
//	Or maybe just all URLs that end with passwd
//	uri~%/etc/passwd
//
//	And to give quoted example, find POSTs with a specific curl command
//	method:POST body~"%curl -k%"
//
// Finally, you can search date fields with < and >
// method:GET created_at<2024-01-6
func ParseQuery(q string, validFields []string) ([][]SearchRequestsParam, error) {
	var ret [][]SearchRequestsParam
	outsideParam := true

	currentParams := make([]SearchRequestsParam, 0)
	for i := 0; i < len(q); {
		if outsideParam && unicode.IsSpace(rune(q[i])) {
			if i+1 >= len(q) {
				return ret, fmt.Errorf("unexpected end of query")
			}

			i++
			continue
		}

		if i < (len(q) - 2) {
			if q[i] == 'O' && q[i+1] == 'R' {
				i += 2

				ret = append(ret, currentParams)
				currentParams = make([]SearchRequestsParam, 0)
				continue

			}
		}

		outsideParam = false

		// This is the start of a keyword. To begin with, we check if the !
		// or - character is there to indicate we want a negative match.
		not := false
		if q[i] == '!' || q[i] == '-' {
			not = true
			if i+1 >= len(q) {
				return ret, fmt.Errorf("unexpected end of query")
			}
			i++
		}

		var keyword strings.Builder
		var separator byte
		for ; i < len(q) && (q[i] != ':' && q[i] != '~' && q[i] != '>' && q[i] != '<'); i++ {
			keyword.WriteByte(q[i])
		}

		if !slices.Contains(validFields, keyword.String()) {
			return ret, fmt.Errorf("unknown search keyword: %s", keyword.String())
		}

		separator = q[i]

		// We move to the start of the value and check if it is between quotes. When
		// between quotes then we will allow spaces.
		if i+1 >= len(q) {
			return ret, fmt.Errorf("unexpected end of query")
		}
		i++

		inQuote := false
		var finishChar byte
		if q[i] == '"' || q[i] == '\'' {
			finishChar = q[i]
			inQuote = true
			if i+1 >= len(q) {
				return ret, fmt.Errorf("unexpected end of query")
			}
			i++
		}

		var value strings.Builder
		if inQuote {
			for ; q[i] != finishChar; i++ {
				// Last character
				if i == (len(q) - 1) {
					return ret, fmt.Errorf("end quote is missing")
				}

				// Skip escaped characters
				if q[i] == '\\' && (i+2) <= (len(q)-1) {
					i++
				}
				value.WriteByte(q[i])
			}
		} else {
			for ; i < len(q) && !unicode.IsSpace(rune(q[i])); i++ {
				value.WriteByte(q[i])
			}
		}

		if i < len(q) {
			i++
		}

		outsideParam = true
		var whereType WhereType
		switch separator {
		case ':':
			whereType = IS
		case '~':
			whereType = LIKE
		case '<':
			whereType = LOWER_THAN
		case '>':
			whereType = GREATER_THAN
		default:
			return ret, fmt.Errorf("unknown separator %c", separator)
		}

		currentParams = append(currentParams, SearchRequestsParam{
			key:      keyword.String(),
			value:    value.String(),
			matching: whereType,
			not:      not,
		})
	}

	if len(currentParams) > 0 {
		ret = append(ret, currentParams)
	}

	return ret, nil
}

// getLabelWhereClause returns the where clause for the request label search.
func getLabelWhereClause(index int, s *SearchRequestsParam) (string, error) {
	switch s.matching {
	case IS:
		if s.not {
			return fmt.Sprintf("id IN (SELECT tag_per_request.request_id FROM tag_per_request join tag ON tag.id = tag_per_request.tag_id AND tag.name != $%d)", index), nil
		}
		return fmt.Sprintf("id IN (SELECT tag_per_request.request_id FROM tag_per_request join tag ON tag.id = tag_per_request.tag_id AND tag.name = $%d)", index), nil
	case LIKE:
		if !strings.Contains(s.value, "%") {
			s.value = fmt.Sprintf("%s%%", s.value)
		}

		if s.not {
			return fmt.Sprintf("id IN (SELECT tag_per_request.request_id FROM tag_per_request join tag ON tag.id = tag_per_request.tag_id AND tag.name NOT LIKE $%d)", index), nil
		}
		return fmt.Sprintf("id IN (SELECT tag_per_request.request_id FROM tag_per_request join tag ON tag.id = tag_per_request.tag_id AND tag.name LIKE $%d)", index), nil
	}

	return "", fmt.Errorf("could not match %+v", s)
}

func getWhereClause(index int, s *SearchRequestsParam) (string, error) {
	switch s.matching {
	case IS:
		if s.not {
			return fmt.Sprintf("%s != $%d", s.key, index), nil
		}
		return fmt.Sprintf("%s = $%d", s.key, index), nil
	case LIKE:
		if !strings.Contains(s.value, "%") {
			s.value = fmt.Sprintf("%s%%", s.value)
		}

		if s.not {
			return fmt.Sprintf("%s NOT LIKE $%d", s.key, index), nil
		}
		return fmt.Sprintf("%s LIKE $%d", s.key, index), nil
	case LOWER_THAN:
		if s.not {
			return fmt.Sprintf("%s >= $%d", s.key, index), nil
		}
		return fmt.Sprintf("%s < $%d", s.key, index), nil

	case GREATER_THAN:
		if s.not {
			return fmt.Sprintf("%s <= $%d", s.key, index), nil
		}
		return fmt.Sprintf("%s > $%d", s.key, index), nil
	}

	return "", fmt.Errorf("could not match %+v", s)
}

// buildComposedQuery creates a query from the given array of parameters arrays.
// Each separate parameter array is treated as a subquery and they are combined
// with OR.
func buildComposedQuery(params [][]SearchRequestsParam, queryPrefix string, querySuffix string) (string, []interface{}, error) {
	baseQuery := queryPrefix

	var values []interface{}

	var subQueries []string
	valueIdx := 1
	for _, paramSet := range params {
		subQuery := ""
		for i, param := range paramSet {

			var wc string
			var err error
			if param.key == "label" {
				wc, err = getLabelWhereClause(valueIdx, &param)
				if err != nil {
					return "", nil, err
				}
			} else {
				wc, err = getWhereClause(valueIdx, &param)
				if err != nil {
					return "", nil, err
				}
			}

			if i == 0 {
				subQuery = wc
				values = append(values, param.value)
			} else {
				subQuery = fmt.Sprintf("%s AND %s", subQuery, wc)
				values = append(values, param.value)
			}
			valueIdx += 1
		}

		subQueries = append(subQueries, subQuery)
	}

	if len(subQueries) > 0 {
		baseQuery = fmt.Sprintf("%s WHERE", baseQuery)
		for i, q := range subQueries {
			if i == 0 {
				baseQuery = fmt.Sprintf("%s (%s)", baseQuery, q)
			} else {
				baseQuery = fmt.Sprintf("%s OR (%s)", baseQuery, q)
			}
		}
	}
	baseQuery = fmt.Sprintf("%s %s", baseQuery, querySuffix)
	return baseQuery, values, nil
}
