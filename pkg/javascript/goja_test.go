package javascript

import (
	"fmt"
	"loophid/pkg/database"
	"testing"
)

func TestRunScriptWithoutValidateOk(t *testing.T) {

	for _, test := range []struct {
		description    string
		script         string
		expectedOutput string
		expectError    bool
	}{
		{
			description:    "runs ok",
			script:         "function createResponse() { return ['OK', '']; }",
			expectedOutput: "OK",
			expectError:    false,
		},
		{
			description:    "can access request (attribute)",
			script:         "function createResponse() { return [request.port, '']; }",
			expectedOutput: "80",
			expectError:    false,
		},
		{
			description:    "can access request (method)",
			script:         "function createResponse() { return [request.modelID(), ''] }",
			expectedOutput: "42",
			expectError:    false,
		},
		{
			description:    "can access request (method, bodyString)",
			script:         "function createResponse() { return [request.bodyString(), ''] }",
			expectedOutput: "the body",
			expectError:    false,
		},
		{
			description:    "returns error string",
			script:         "function createResponse() { return [request.port, 'ERROR']; }",
			expectedOutput: "",
			expectError:    true,
		},
		{
			description:    "misses hook",
			script:         "1+1",
			expectedOutput: "",
			expectError:    true,
		},
		{
			description:    "invalid javascript",
			script:         "1+1';[/l879.",
			expectedOutput: "",
			expectError:    true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			req := database.Request{
				ID:   42,
				Port: 80,
				Uri:  "/foo",
				Body: []byte("the body"),
			}

			jr := NewGojaJavascriptRunner()

			out, err := jr.RunScript(test.script, req, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if out != test.expectedOutput {
				t.Errorf("got %s, wanted %s", out, test.expectedOutput)
			}
		})

	}
}

func TestRunScriptWithValidateOk(t *testing.T) {

	for _, test := range []struct {
		description string
		script      string
		expectError bool
	}{
		{
			description: "runs ok",
			script: `
			function __validate() {
				const res = createResponse();
				if (res[0] != 'OK') {
					return "Did not find OK";
				}
			}
			function createResponse() {
				return ['OK', ''];
			}
			`,
			expectError: false,
		},
		{
			description: "fails ok",
			script: `
			function __validate() {
				const res = createResponse();
				if (res[0] != 'SOMETHING ELSE') {
					return "Did not find OK";
				}
			}
			function createResponse() {
				return ['OK', ''];
			}
			`,
			expectError: true,
		},
		{
			description: "has no validate method",
			script: `
			function createResponse() {
				return ['OK', ''];
			}
			`,
			expectError: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			req := database.Request{
				ID:   42,
				Port: 80,
				Uri:  "/foo",
				Body: []byte("the body"),
			}

			jr := NewGojaJavascriptRunner()
			_, err := jr.RunScript(test.script, req, true)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}
		})

	}
}
