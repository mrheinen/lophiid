package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringToMD5(t *testing.T) {
	toolSet := &CodeToolSet{}

	result, err := toolSet.StringToMD5("hello")

	assert.NoError(t, err)
	assert.Equal(t, "5d41402abc4b2a76b9719d911017c592", result)
}

func TestStringFromBase64(t *testing.T) {
	toolSet := &CodeToolSet{}

	result, err := toolSet.StringFromBase64("aGVsbG8gd29ybGQ=")

	assert.NoError(t, err)
	assert.Equal(t, "hello world", result)
}

func TestStringFromBase64_InvalidInput(t *testing.T) {
	toolSet := &CodeToolSet{}

	result, err := toolSet.StringFromBase64("not-valid-base64!!!")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error decoding base64")
	assert.Empty(t, result)
}
