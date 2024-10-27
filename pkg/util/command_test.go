package util

import (
	"reflect"
	"testing"
)

func TestSplitCommandsOnSemi(t *testing.T) {

	for _, test := range []struct {
		description string
		commands    string
		output      []string
	}{
		{
			description: "simple multiple command string",
			commands:    "ls; ps ax",
			output:      []string{"ls", "ps ax"},
		},
		{
			description: "simple single command string",
			commands:    "ls",
			output:      []string{"ls"},
		},
		{
			description: "trailing semi",
			commands:    "ls;",
			output:      []string{"ls"},
		},
		{
			description: "leading semi",
			commands:    ";ls",
			output:      []string{"ls"},
		},
		{
			description: "empty semi",
			commands:    "; ",
			output:      []string{},
		},
		{
			description: "escaped semi",
			commands:    "echo \\;aa ",
			output:      []string{"echo \\;aa"},
		},
		{
			description: "trailing escaped",
			commands:    "echo \\",
			output:      []string{"echo \\"},
		},
		{
			description: "quoted semi ignored",
			commands:    "echo ';aa'",
			output:      []string{"echo ';aa'"},
		},
		{
			description: "escaped quote ignored",
			commands:    "echo '\\';';ls",
			output:      []string{"echo '\\';'", "ls"},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			res := SplitCommandsOnSemi(test.commands)

			if !reflect.DeepEqual(res, test.output) {
				t.Errorf("got %+#v, want %+#v", res, test.output)
			}

		})

	}

}
