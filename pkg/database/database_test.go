package database

import (
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
		result        []SearchRequestsParam
	}{
		{
			description:   "parse simple IS",
			queryString:   "source_ip:1.1.1.1",
			errorContains: "",
			validFields:   []string{"source_ip"},
			result: []SearchRequestsParam{
				{
					key:      "source_ip",
					value:    "1.1.1.1",
					matching: IS,
				},
			},
		},
		{
			description:   "parse greater than",
			queryString:   "port>80",
			errorContains: "",
			validFields:   []string{"port"},
			result: []SearchRequestsParam{
				{
					key:      "port",
					value:    "80",
					matching: GREATER_THAN,
				},
			},
		},
		{
			description:   "parse lower than",
			queryString:   "port<80",
			errorContains: "",
			validFields:   []string{"port"},
			result: []SearchRequestsParam{
				{
					key:      "port",
					value:    "80",
					matching: LOWER_THAN,
				},
			},
		},
		{
			description:   "parse like",
			queryString:   "uri~%test%",
			errorContains: "",
			validFields:   []string{"uri"},
			result: []SearchRequestsParam{
				{
					key:      "uri",
					value:    "%test%",
					matching: LIKE,
				},
			},
		},
		{
			description:   "parse simple IS quoted",
			queryString:   "source_ip:'1.1.1.1'",
			errorContains: "",
			validFields:   []string{"source_ip"},
			result: []SearchRequestsParam{
				{
					key:      "source_ip",
					value:    "1.1.1.1",
					matching: IS,
				},
			},
		},
		{
			description:   "parse simple IS quoted with space",
			queryString:   "uri:'this is spaced'",
			errorContains: "",
			validFields:   []string{"uri"},
			result: []SearchRequestsParam{
				{
					key:      "uri",
					value:    "this is spaced",
					matching: IS,
				},
			},
		},
		{
			description:   "complex query",
			queryString:   "source_ip:'1.1.1.1' port>80",
			errorContains: "",
			validFields:   []string{"source_ip", "port"},
			result: []SearchRequestsParam{
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

		{
			description:   "unknown keyworde",
			queryString:   "foo:bar",
			errorContains: "unknown search",
			validFields:   []string{"notfoo"},
			result:        []SearchRequestsParam{},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res, err := parseQuery(test.queryString, test.validFields)
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
