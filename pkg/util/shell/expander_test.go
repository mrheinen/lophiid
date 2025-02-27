package shell

import (
	"lophiid/pkg/util"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandVariables(t *testing.T) {

	for _, test := range []struct {
		description    string
		inputBuffer    []byte
		expectedOutput []string
	}{
		{
			description:    "simple variable declaration",
			inputBuffer:    []byte("AAA=123\n$AAA $AAA"),
			expectedOutput: []string{"AAA=123", "123 123"},
		},
		{
			description:    "Common env variables",
			inputBuffer:    []byte("$HOME\n$USER"),
			expectedOutput: []string{"/root", "root"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			exp := NewExpander()
			rdr := ScriptIterator{}
			rdr.FromBuffer(test.inputBuffer)

			res := exp.Expand(&rdr)

			if len(res) != len(test.expectedOutput) {
				t.Fatalf("expected %d, got %d", len(test.expectedOutput), len(res))
			}

			if !util.AreSlicesEqual(res, test.expectedOutput) {
				t.Errorf("expected %s, got %s", test.expectedOutput, res)
			}

		})
	}
}

func TestExpandForLoop(t *testing.T) {

	for _, test := range []struct {
		description    string
		fileData       []byte
		expectedOutput []string
	}{
		{
			description: "simple for loop",
			fileData: []byte(`
for VARIABLE in 1 2 3 4 5
do
echo $VARIABLE
done`),

			expectedOutput: []string{"echo 1", "echo 2", "echo 3", "echo 4", "echo 5"},
		},
		{
			description: "for loop based on variable",
			fileData: []byte(`
VALS="1 2 3 4 5"
for VARIABLE in $VALS
do
echo $VARIABLE
done`),

			expectedOutput: []string{
				"VALS=\"1 2 3 4 5\"", "echo 1", "echo 2", "echo 3", "echo 4", "echo 5"},
		},
		{
			description: "for loop based on quoted variable",
			fileData: []byte(`
for VARIABLE in "aa bb cc"
do
echo $VARIABLE
done`),

			expectedOutput: []string{
				"echo aa", "echo bb", "echo cc"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			exp := NewExpander()
			rdr := ScriptIterator{}
			rdr.FromBuffer(test.fileData)

			res := exp.Expand(&rdr)

			assert.Equal(t, test.expectedOutput, res, "should be equal")

		})
	}
}

func TestGetCommandOutput(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantErr       bool
		errorContains string
	}{
		{
			name:          "input too short",
			input:         "$(",
			wantErr:       true,
			errorContains: "value too short",
		},
		{
			name:          "unknown command",
			input:         "$(unknown-command)",
			wantErr:       true,
			errorContains: "unknown command",
		},
		{
			name:    "valid command with single output",
			input:   "$(uname -i)",
			wantErr: false,
		},
		{
			name:    "valid command with multiple outputs",
			input:   "$(uname -mp)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCommandOutput(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				return
			}
			assert.NoError(t, err)

			if tt.input == "$(uname -i)" {
				// For single output commands, verify it's one of the expected values
				assert.Contains(t, commandOutputs["uname -i"], got)
			} else if tt.input == "$(uname -mp)" {
				// For multiple output commands, verify it's one of the expected values
				assert.Contains(t, commandOutputs["uname -mp"], got)
			}
		})
	}
}

func TestCleanupVariableValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "string with single quotes",
			input:    "'test value'",
			expected: "test value",
		},
		{
			name:     "string with double quotes",
			input:    "\"test value\"",
			expected: "test value",
		},
		{
			name:     "string without quotes",
			input:    "test value",
			expected: "test value",
		},
		{
			name:     "string with whitespace",
			input:    "  test value  ",
			expected: "test value",
		},
		{
			name:     "short quoted string",
			input:    "'a'",
			expected: "'a'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CleanupVariableValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
