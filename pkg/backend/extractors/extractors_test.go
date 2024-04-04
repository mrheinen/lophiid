package extractors

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
				roughDecodeURL(v.input)
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
			res := roughDecodeURL(test.stringToDecode)
			if res != test.expectedResult {
				t.Errorf("got %s, expected %s", res, test.expectedResult)
			}
		})
	}
}
