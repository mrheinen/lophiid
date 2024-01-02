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
		result        []SearchRequestsParam
	}{
		{
			description:   "parse simple IS",
			queryString:   "source_ip:1.1.1.1",
			errorContains: "",
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
			result: []SearchRequestsParam{
				{
					key:      "uri",
					value:    "%test%",
					matching: LIKE,
				},
			},
		},
		{
			description:   "unknown keyworde",
			queryString:   "foo:bar",
			errorContains: "unknown search",
			result:        []SearchRequestsParam{},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res, err := parseQuery(test.queryString)
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
