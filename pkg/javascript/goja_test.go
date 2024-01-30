package javascript

import (
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/database"
	"testing"
)

func TestRunScriptWithoutValidateOk(t *testing.T) {

	for _, test := range []struct {
		description         string
		script              string
		expectedOutput      string
		expectedHeader      string
		expectedHeaderValue string
		expectError         bool
	}{
		{
			description:         "runs ok",
			script:              "function createResponse() { response.setBody('OK'); }",
			expectedOutput:      "OK",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         false,
		},
		{
			description:         "can access request (attribute)",
			script:              "function createResponse() { response.setBody(request.port); }",
			expectedOutput:      "80",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         false,
		},
		{
			description:         "can access request (method)",
			script:              "function createResponse() { response.setBody(request.modelID()); }",
			expectedOutput:      "42",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         false,
		},
		{
			description:         "set response header",
			script:              "function createResponse() { response.addHeader('key', 'value'); }",
			expectedOutput:      "",
			expectedHeader:      "key",
			expectedHeaderValue: "value",
			expectError:         false,
		},

		{
			description:         "returns error string",
			script:              "function createResponse() { return 'ERROR'; }",
			expectedOutput:      "",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         true,
		},
		{
			description:         "misses hook",
			script:              "1+1",
			expectedOutput:      "",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         true,
		},
		{
			description:         "invalid javascript",
			script:              "1+1';[/l879.",
			expectedOutput:      "",
			expectedHeader:      "",
			expectedHeaderValue: "",
			expectError:         true,
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

			res := backend_service.HttpResponse{}

			err := jr.RunScript(test.script, req, &res, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if string(res.Body) != test.expectedOutput {
				t.Errorf("got %s, wanted %s", res.Body, test.expectedOutput)
			}

			if test.expectedHeader != "" {
				found := false
				for _, h := range res.Header {
					if h.Key == test.expectedHeader && h.Value == test.expectedHeaderValue {
						found = true
						break
					}
				}

				if !found {
					t.Errorf("did not find header: %s in %v", test.expectedHeader, &res)
				}
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
				if (res != '') {
					return "Found: " + res;
				}
			}
			function createResponse() {
				return '';
			}
			`,
			expectError: false,
		},
		{
			description: "runs NOT ok",
			script: `
			function __validate() {
				const res = createResponse();
				if (res != '') {
					return "Found: " + res;
				}
			}
			function createResponse() {
				return 'OOOPS';
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

			res := backend_service.HttpResponse{}
			jr := NewGojaJavascriptRunner()
			err := jr.RunScript(test.script, req, &res, true)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}
		})

	}
}
