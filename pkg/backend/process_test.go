package backend

import (
	"testing"
)

func TestFindBase64Strings(t *testing.T) {
	for _, test := range []struct {
		description    string
		stringToSearch string
		base64sToFind  []string
	}{
		{
			description:    "finds full match",
			stringToSearch: "aGVsbG8=",
			base64sToFind:  []string{"aGVsbG8="},
		},
		{
			description:    "finds with rubbish after padding",
			stringToSearch: "aGVsbG8=aa YQ==333",
			base64sToFind:  []string{"aGVsbG8=", "YQ=="},
		},
		{
			description:    "finds multiple",
			stringToSearch: "aGVsbG8= d29ybGQ=",
			base64sToFind:  []string{"aGVsbG8=", "d29ybGQ="},
		},
		{
			description:    "recovers invalid prefix",
			stringToSearch: "+aGVsbG8=",
			base64sToFind:  []string{"aGVsbG8="},
		},
		{
			description:    "ignores invalid",
			stringToSearch: "aGVsbG8",
			base64sToFind:  []string{},
		},
		{
			description:    "ignores to small",
			stringToSearch: "a=",
			base64sToFind:  []string{},
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			res := FindBase64Strings(test.stringToSearch)
			if len(res) != len(test.base64sToFind) {
				t.Errorf("expected %d base64s but found %d", len(test.base64sToFind), len(res))
			}

			for _, v := range test.base64sToFind {
				_, ok := res[v]
				if !ok {
					t.Errorf("expected to find %s in %v", v, res)
				}
			}
		})
	}
}
