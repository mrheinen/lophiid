package database

import (
	"fmt"
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
// is wanted. The supported seperators are:
//    :    - match exactly
//    >    - greater than
//    <    - lower than
//    ~    - like/contains (use with percentages)
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

func ParseQuery(q string, validFields []string) ([]SearchRequestsParam, error) {
	var ret []SearchRequestsParam
	outsideParam := true

	for i := 0; i < len(q); {
		if outsideParam && unicode.IsSpace(rune(q[i])) {
			i++
			continue
		}

		outsideParam = false

		// This is the start of a keyword. To begin with, we check if the !
		// or - character is there to indicate we want a negative match.
		not := false
		if q[i] == '!' || q[i] == '-' {
			not = true
			i++
		}

		var keyword strings.Builder
		var separator byte
		for ; i < len(q) && (q[i] != ':' && q[i] != '~' && q[i] != '>' && q[i] != '<'); i++ {
			keyword.WriteByte(q[i])
		}

		hasField := false
		for _, field := range validFields {
			if field == keyword.String() {
				hasField = true
				break
			}
		}

		if !hasField {
			return ret, fmt.Errorf("unknown search keyword: %s", keyword.String())
		}

		separator = q[i]

		// We move to the start of the value and check if it is between quotes. When
		// between quotes then we will allow spaces.
		i++
		inQuote := false
		var finishChar byte
		if q[i] == '"' || q[i] == '\'' {
			finishChar = q[i]
			inQuote = true
			i++
		}

		var value strings.Builder
		if inQuote {
			for ; i < len(q) && q[i] != finishChar; i++ {
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
			return ret, fmt.Errorf("unknown seperator %c", separator)
		}

		ret = append(ret, SearchRequestsParam{
			key:      keyword.String(),
			value:    value.String(),
			matching: whereType,
			not:      not,
		})
	}

	return ret, nil
}

func getWhereClause(index int, s *SearchRequestsParam) (string, error) {
	switch s.matching {
	case IS:
		if s.not {
			return fmt.Sprintf("%s != $%d ", s.key, index), nil
		}
		return fmt.Sprintf("%s = $%d ", s.key, index), nil
	case LIKE:
		if !strings.Contains(s.value, "%") {
			s.value = fmt.Sprintf("%s%%", s.value)
		}

		if s.not {
			return fmt.Sprintf("%s NOT LIKE $%d ", s.key, index), nil
		}
		return fmt.Sprintf("%s LIKE $%d ", s.key, index), nil
	case LOWER_THAN:
		if s.not {
			return fmt.Sprintf("%s >= $%d ", s.key, index), nil
		}
		return fmt.Sprintf("%s < $%d ", s.key, index), nil

	case GREATER_THAN:
		if s.not {
			return fmt.Sprintf("%s <= $%d ", s.key, index), nil
		}
		return fmt.Sprintf("%s > $%d ", s.key, index), nil
	}

	return "", fmt.Errorf("could not match %+v", s)
}

func buildQuery(params []SearchRequestsParam, queryPrefix string, querySuffix string) (string, []interface{}, error) {
	baseQuery := queryPrefix

	idx := 1
	var values []interface{}
	for _, param := range params {
		wc, err := getWhereClause(idx, &param)
		if err != nil {
			return "", nil, err
		}
		if idx == 1 {
			baseQuery = fmt.Sprintf("%s WHERE %s", baseQuery, wc)
			values = append(values, param.value)
		} else {
			baseQuery = fmt.Sprintf("%s AND %s", baseQuery, wc)
			values = append(values, param.value)
		}
		idx++
	}

	baseQuery = fmt.Sprintf("%s %s", baseQuery, querySuffix)
	return baseQuery, values, nil
}
