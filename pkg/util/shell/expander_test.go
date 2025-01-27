package shell

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandVariables(t *testing.T) {

	exp := NewExpander()

	rdr := ScriptIterator{}
	rdr.FromBuffer([]byte("AAAA=123\n$AAAA $AAAA"))

	res := exp.Expand(&rdr)

	fmt.Printf("%s\n", res)

	if len(res) != 2 {
		t.Errorf("2, got %d", len(res))
	}

	if res[1] != "123 123" {
		t.Errorf("123 123, got %s", res[0])
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
