package util

import "testing"

func TestIsValidUUID(t *testing.T) {

	for _, test := range []struct {
		description string
		uuid        string
		valid       bool
	}{
		{
			description: "UUID is valid",
			uuid:        "a5c5f7c9-9b0f-4f6d-8a7d-3c6b9e0f6d8a",
			valid:       true,
		},
		{
			description: "UUID is valid - mixed case",
			uuid:        "a5c5f7c9-9b0f-4f6d-8A7D-3c6b9e0f6d8a",
			valid:       true,
		},

		{
			description: "UUID is not corrupt",
			uuid:        "a5c5f7c9-9b-4f6d-8a7d-3c6b9e0f6d8a",
			valid:       false,
		},
		{
			description: "UUID has invalid chars",
			uuid:        "a5c5fXXX-9b-4f6d-8a7d-3c6b9e0f6d8a",
			valid:       false,
		},

	} {

		t.Run(test.description, func(t *testing.T) {
			res := IsValidUUID(test.uuid)
			if res != test.valid {
				t.Errorf("got %v, want %v", res, test.valid)
			}
		})

	}
}

func TestIsAscii(t *testing.T) {

	for _, test := range []struct {
		description string
		string        string
		isAscii       bool
	}{
		{
			description: "is ascii",
			string:        "sadsdssdsd",
			isAscii:       true,
		},
		{
			description: "is not valid",
			string:        "\xff\xff\xfe\x0a",
			isAscii:       false,
		},


	} {

		t.Run(test.description, func(t *testing.T) {
			res := IsStringASCII(test.string)
			if res != test.isAscii {
				t.Errorf("got %v, want %v", res, test.isAscii)
			}
		})
	}
}
