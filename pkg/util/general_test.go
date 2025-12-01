package util

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFastCacheHash verifies that different inputs produce different hashes.
// This is a regression test for a bug where the hash was not being returned
// correctly, causing all inputs to produce the same hash (128 zero bytes).
func TestFastCacheHash(t *testing.T) {
	hash1 := FastCacheHash("hello world")
	hash2 := FastCacheHash("different input")
	hash3 := FastCacheHash("hello world") // Same as hash1

	// Different inputs must produce different hashes
	assert.False(t, bytes.Equal(hash1, hash2), "Different inputs should produce different hashes")

	// Same input must produce same hash
	assert.True(t, bytes.Equal(hash1, hash3), "Same input should produce same hash")

	// Hash should not be all zeros (the bug produced 128 zero bytes)
	allZeros := make([]byte, len(hash1))
	assert.False(t, bytes.Equal(hash1, allZeros), "Hash should not be all zeros")

	// FNV-128a produces 16-byte hash
	assert.Equal(t, 16, len(hash1), "FNV-128a should produce 16-byte hash")
}

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
