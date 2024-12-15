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
package decoding

import (
	"fmt"
	"testing"
)

var table = []struct {
	input string
}{
	{input: "%22 sdd dsd s %25 sds %41"},
	{input: "%22 %7d %7e %25"},
	{input: "%22 %FF %7e %25"},
}

func BenchmarkSadencodeURL(b *testing.B) {
	for _, v := range table {
		b.Run(fmt.Sprintf("input_%s", v.input), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				RoughDecodeURL(v.input)
			}
		})
	}
}

func TestRoughDencodeURL(t *testing.T) {
	for _, test := range []struct {
		description    string
		stringToDecode string
		expectedResult string
	}{
		{
			description:    "finds full url",
			stringToDecode: "haha%22",
			expectedResult: "haha\"",
		},
		{
			description:    "traversal lowercase",
			stringToDecode: "%2e%2e%2f",
			expectedResult: "../",
		},
		{
			description:    "ignores trailing %",
			stringToDecode: "truncated string %",
			expectedResult: "truncated string %",
		},
		{
			description:    "ignores non ascii char",
			stringToDecode: "aa %FF",
			expectedResult: "aa %FF",
		},
		{
			description:    "ignores lingering %",
			stringToDecode: "aa % sdfsfdfd",
			expectedResult: "aa % sdfsfdfd",
		},
		{
			description:    "does not crash",
			stringToDecode: "aa %d",
			expectedResult: "aa %d",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res := RoughDecodeURL(test.stringToDecode)
			if res != test.expectedResult {
				t.Errorf("got %s, expected %s", res, test.expectedResult)
			}
		})
	}
}

func TestDecodeURLOrEmptyString(t *testing.T) {
	for _, test := range []struct {
		description    string
		stringToDecode string
		removeSpace    bool
		expectedResult string
	}{
		{
			description:    "simple url encoded string",
			stringToDecode: "hello%20world",
			removeSpace:    false,
			expectedResult: "hello world",
		},
		{
			description:    "plus sign with removeSpace true",
			stringToDecode: "hello+world",
			removeSpace:    true,
			expectedResult: "hello world",
		},
		{
			description:    "plus sign with removeSpace false",
			stringToDecode: "hello+world",
			removeSpace:    false,
			expectedResult: "hello+world",
		},
		{
			description:    "double encoded string",
			stringToDecode: "hello%2520world", // "hello%20world" encoded once more
			removeSpace:    false,
			expectedResult: "hello world",
		},
		{
			description:    "invalid encoding falls back to rough decode",
			stringToDecode: "hello%2world%20test",
			removeSpace:    false,
			expectedResult: "hello%2world test",
		},
		{
			description:    "empty string",
			stringToDecode: "",
			removeSpace:    false,
			expectedResult: "",
		},
		{
			description:    "special characters",
			stringToDecode: "%21%40%23%24%25%5E%26%2A%28%29",
			removeSpace:    false,
			expectedResult: "!@#$%^&*()",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			result := DecodeURLOrEmptyString(test.stringToDecode, test.removeSpace)
			if result != test.expectedResult {
				t.Errorf("expected %q but got %q", test.expectedResult, result)
			}
		})
	}
}
