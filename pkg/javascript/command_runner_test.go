package javascript

import (
	"fmt"
	"testing"
)

func TestSingleCommandRunner_RunCommand(t *testing.T) {
	allowedCommands := []string{"ls", "echo", "false"}

	tests := []struct {
		name            string
		command         string
		args            []string
		expectedSuccess bool
		expectedOutput  string
		expectedError   error
	}{
		{
			name:            "Allowed command succeeds",
			command:         "ls",
			args:            nil,
			expectedSuccess: true,
			expectedOutput:  "",
			expectedError:   nil,
		},
		{
			name:            "Disallowed command fails",
			command:         "rm",
			args:            []string{"-rf", "/tmp/aa"},
			expectedSuccess: false,
			expectedOutput:  "",
			expectedError:   fmt.Errorf("command rm is not allowed"),
		},
		{
			name:            "Command with arguments",
			command:         "echo",
			args:            []string{"Hello", "World!"},
			expectedSuccess: true,
			expectedOutput:  "Hello World!\n",
			expectedError:   nil,
		},
		{
			name:            "Command fails",
			command:         "false",
			args:            nil,
			expectedSuccess: false,
			expectedOutput:  "",
			expectedError:   fmt.Errorf("exit status 1"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := NewSingleCommandRunner(allowedCommands)
			success := runner.RunCommand(test.command, test.args...)

			if success != test.expectedSuccess {
				t.Errorf("expected success: %v, but got: %v", test.expectedSuccess, success)
			}

			if test.expectedOutput != "" && runner.Stdout.String() != test.expectedOutput {
				t.Errorf("expected output: '%s', but got: '%s'", test.expectedOutput, runner.Stdout.String())
			}

			if test.expectedError != nil && runner.Error == nil {
				t.Error("expected an error, but got nil")
			} else if test.expectedError != nil && runner.Error.Error() != test.expectedError.Error() {
				t.Errorf("expected error: '%s', but got: '%s'", test.expectedError, runner.Error)
			}
		})
	}
}
