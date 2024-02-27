package database

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseQuery(t *testing.T) {
	for _, test := range []struct {
		description   string
		queryString   string
		errorContains string
		validFields   []string
		result        [][]SearchRequestsParam
	}{
		{
			description:   "parse simple IS",
			queryString:   "source_ip:1.1.1.1",
			errorContains: "",
			validFields:   []string{"source_ip"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
				},
			},
		},

		{
			description:   "parse simple NOT IS",
			queryString:   "!source_ip:1.1.1.1",
			errorContains: "",
			validFields:   []string{"source_ip"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
						not:      true,
					},
				},
			},
		},
		{
			description:   "parse greater than",
			queryString:   "port>80",
			errorContains: "",
			validFields:   []string{"port"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "port",
						value:    "80",
						matching: GREATER_THAN,
					},
				},
			},
		},
		{
			description:   "parse lower than",
			queryString:   "port<80",
			errorContains: "",
			validFields:   []string{"port"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "port",
						value:    "80",
						matching: LOWER_THAN,
					},
				},
			},
		},
		{
			description:   "parse like",
			queryString:   "uri~%test%",
			errorContains: "",
			validFields:   []string{"uri"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "uri",
						value:    "%test%",
						matching: LIKE,
					},
				},
			},
		},
		{
			description:   "parse simple IS quoted",
			queryString:   "source_ip:'1.1.1.1'",
			errorContains: "",
			validFields:   []string{"source_ip"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "parse simple IS quoted with space",
			queryString:   "uri:'this is spaced'",
			errorContains: "",
			validFields:   []string{"uri"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "uri",
						value:    "this is spaced",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "complex query",
			queryString:   "source_ip:'1.1.1.1' port>80",
			errorContains: "",
			validFields:   []string{"source_ip", "port"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
					{
						key:      "port",
						value:    "80",
						matching: GREATER_THAN,
					},
				},
			},
		},
		{
			description:   "simple query with subqueries",
			queryString:   "source_ip:'1.1.1.1' OR port>80 OR method:GET",
			errorContains: "",
			validFields:   []string{"source_ip", "port", "method"},
			result: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
				},
				{
					{
						key:      "port",
						value:    "80",
						matching: GREATER_THAN,
					},
				},
				{
					{
						key:      "method",
						value:    "GET",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "unknown keyword",
			queryString:   "foo:bar",
			errorContains: "unknown search",
			validFields:   []string{"notfoo"},
			result:        [][]SearchRequestsParam{},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("Running test: %s\n", test.description)
			res, err := ParseQuery(test.queryString, test.validFields)
			if test.errorContains != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("expected \"%s\" in \"%s\"", err.Error(), test.errorContains)
				}
			} else {

				if len(res) != len(test.result) {
					t.Errorf("expected len %d but go %d", len(test.result), len(res))
				}

				if !reflect.DeepEqual(res, test.result) {
					t.Errorf("%+v is not %+v", test.result, res)
				}
			}
		})
	}
}

func TestBuildComposedQuery(t *testing.T) {
	for _, test := range []struct {
		description   string
		queryPrefix   string
		querySuffix   string
		resultQuery   string
		errorContains string
		params        [][]SearchRequestsParam
	}{
		{
			description:   "single where",
			errorContains: "",
			queryPrefix:   "SELECT * FROM table",
			querySuffix:   "LIMIT 10",
			resultQuery:   "SELECT * FROM table WHERE (source_ip = $1) LIMIT 10",

			params: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "multiple ands",
			errorContains: "",
			queryPrefix:   "SELECT * FROM table",
			querySuffix:   "LIMIT 10",
			resultQuery:   "SELECT * FROM table WHERE (source_ip = $1 AND port = $2) LIMIT 10",

			params: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},

					{
						key:      "port",
						value:    "80",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "multiple subqueries",
			errorContains: "",
			queryPrefix:   "SELECT * FROM table",
			querySuffix:   "LIMIT 10",
			resultQuery:   "SELECT * FROM table WHERE (source_ip = $1) OR (port = $2) LIMIT 10",

			params: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
				},
				{
					{
						key:      "port",
						value:    "80",
						matching: IS,
					},
				},
			},
		},
		{
			description:   "multiple subqueries, complex",
			errorContains: "",
			queryPrefix:   "SELECT * FROM table",
			querySuffix:   "LIMIT 10",
			resultQuery:   "SELECT * FROM table WHERE (source_ip = $1 AND method = $2) OR (port = $3) LIMIT 10",
			params: [][]SearchRequestsParam{
				{
					{
						key:      "source_ip",
						value:    "1.1.1.1",
						matching: IS,
					},
					{
						key:      "method",
						value:    "GET",
						matching: IS,
					},
				},
				{
					{
						key:      "port",
						value:    "80",
						matching: IS,
					},
				},
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("Running test: %s\n", test.description)

			query, _, err := buildComposedQuery(test.params, test.queryPrefix, test.querySuffix)

			if test.errorContains == "" {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			} else {
				if err == nil {
					t.Error("expected error but got none")
				} else if !strings.Contains(err.Error(), test.errorContains) {
					t.Errorf("expected err to contain '%s' but got : %s", test.errorContains, err)
				}
			}

			if query != test.resultQuery {
				t.Errorf("expected '%s', got '%s'", test.resultQuery, query)
			}
		})
	}
}
