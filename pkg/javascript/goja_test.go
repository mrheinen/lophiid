// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package javascript

import (
	"fmt"
	"lophiid/backend_service"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/database"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

			fdb := database.FakeDatabaseClient{}

			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)
			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, []string{}, time.Minute, &fRes, metrics)

			res := backend_service.HttpResponse{}
			eCol := extractors.NewExtractorCollection(true)

			err := jr.RunScript(test.script, req, &res, eCol, false)
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

			fdb := database.FakeDatabaseClient{}

			eCol := extractors.NewExtractorCollection(true)
			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)
			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, []string{}, time.Minute, &fRes, metrics)
			err := jr.RunScript(test.script, req, &res, eCol, true)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}
		})

	}
}

func TestRunScriptUsesCache(t *testing.T) {

	for _, test := range []struct {
		description string
		script1     string
		script2     string
		request1    database.Request
		request2    database.Request
		expectError bool
	}{
		{
			description: "runs ok",
			script1: `
			function createResponse() {
				util.cache.set("hello", "world");
				return '';
			}
			`,
			script2: `
			function createResponse() {
				const ret = util.cache.get("hello");
				if (ret == "world") {
          return '';
				}
				return "got: " + ret;
			}
			`,
			request1: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			request2: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			expectError: false,
		},
		{
			description: "fails because two different source IPs",
			script1: `
			function createResponse() {
				util.cache.set("hello", "world");
				return '';
			}
			`,
			script2: `
			function createResponse() {
				const ret = util.cache.get("hello");
				if (ret == "world") {
          return '';
				}
				return "got: " + ret;
			}
			`,
			request1: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			request2: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "3.3.3.3",
				HoneypotIP: "2.2.2.2",
			},
			expectError: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			res := backend_service.HttpResponse{}
			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)

			fdb := database.FakeDatabaseClient{}

			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, []string{}, time.Minute, &fRes, metrics)

			eCol := extractors.NewExtractorCollection(true)
			jr.RunScript(test.script1, test.request1, &res, eCol, false)
			err := jr.RunScript(test.script2, test.request2, &res, eCol, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if !test.expectError {
				metric := testutil.ToFloat64(metrics.javascriptSuccessCount.WithLabelValues(RunSuccess))
				if metric != 2 {
					t.Errorf("expected success metrics to be 2, got %f", metric)
				}
			}
		})

	}
}

func TestRunScriptUsesDatabase(t *testing.T) {

	for _, test := range []struct {
		description string
		script      string
		request     database.Request
		content     database.Content
		expectError bool
	}{
		{
			description: "runs ok",
			script: `
			function createResponse() {
				var c = util.database.getContentById(42);
				if (c.getID() != 42) {
					return "error";
				}

				return '';
			}
			`,
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			content: database.Content{
				ID:   42,
				Data: []byte("test"),
			},
			expectError: false,
		},
		{
			description: "handle wrong ID ok",
			script: `
			function createResponse() {
				var c = util.database.getContentById(55);
				if (c == null || c.getID() != 55) {
					return "error";
				}

				return '';
			}
			`,
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			content: database.Content{
				ID:   42,
				Data: []byte("test"),
			},
			expectError: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			res := backend_service.HttpResponse{}
			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)

			fdb := database.FakeDatabaseClient{
				ContentsToReturn: map[int64]database.Content{
					42: test.content,
				},
			}

			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, []string{}, time.Minute, &fRes, metrics)

			eCol := extractors.NewExtractorCollection(true)
			err := jr.RunScript(test.script, test.request, &res, eCol, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if !test.expectError {
				metric := testutil.ToFloat64(metrics.javascriptSuccessCount.WithLabelValues(RunSuccess))
				if metric != 1 {
					t.Errorf("expected success metrics to be 1, got %f", metric)
				}
			}
		})
	}
}

func TestRunScriptRunsCommands(t *testing.T) {
	for _, test := range []struct {
		description string
		script      string
		request     database.Request
		content     database.Content
		allowedCmds []string
		cmdTimeout  time.Duration
		expectError bool
	}{
		{
			description: "runs ok",
			script: `
			function createResponse() {
				var r = util.runner.getCommandRunner();
			  if (!r.runCommand("/bin/echo", "aaa")) {
					return 'command not allowed?';
				}
				return r.getStderr();
			}
			`,
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			allowedCmds: []string{"/bin/echo"},
			cmdTimeout:  time.Minute,
			content: database.Content{
				ID:   42,
				Data: []byte("test"),
			},
			expectError: false,
		},
		{
			description: "command not allowed and does not run",
			script: `
			function createResponse() {
				var r = util.runner.getCommandRunner();
			  if (!r.runCommand("/bin/echo", "aaa")) {
					return 'fail is good in this case';
				}
				return '';
			}
			`,
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			allowedCmds: []string{"/bin/false"},
			cmdTimeout:  time.Minute,
			content: database.Content{
				ID:   42,
				Data: []byte("test"),
			},
			expectError: true,
		},
		{
			description: "runs ok",
			script: `
			function createResponse() {
				var r = util.runner.getCommandRunner();
			  if (!r.runCommand("/usr/bin/sleep", 1)) {
					return 'command failed';
				}
				return r.getStderr();
			}
			`,
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
			},
			allowedCmds: []string{"/usr/bin/sleep"},
			cmdTimeout:  time.Millisecond,
			content: database.Content{
				ID:   42,
				Data: []byte("test"),
			},
			expectError: true,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			res := backend_service.HttpResponse{}
			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)

			fdb := database.FakeDatabaseClient{}

			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, test.allowedCmds, test.cmdTimeout, &fRes, metrics)

			eCol := extractors.NewExtractorCollection(true)
			err := jr.RunScript(test.script, test.request, &res, eCol, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if !test.expectError {
				metric := testutil.ToFloat64(metrics.javascriptSuccessCount.WithLabelValues(RunSuccess))
				if metric != 1 {
					t.Errorf("expected success metrics to be 1, got %f", metric)
				}
			}
		})
	}
}

func TestRunScriptHasContext(t *testing.T) {
	for _, test := range []struct {
		description string
		script      string
		request     database.Request
		content     database.Content
		expectError bool
	}{
		{
			description: "runs ok",
			script: fmt.Sprintf(`
			function createResponse() {
				var metadatas = util.context.requestMetadataByType("%s");
				if (metadatas.length != 1) {
					return "Did not find decoded string";
				}
				if (metadatas[0].data != "throw new Exception('id'.execute().text);") {
					return "Unexpected decoded string";
				}
				return "";
			}
			`, constants.ExtractorTypeUnicode),
			request: database.Request{
				ID:         42,
				Port:       80,
				Uri:        "/foo",
				SourceIP:   "1.1.1.1",
				HoneypotIP: "2.2.2.2",
				Body:       []byte(`groovyProgram=\u0074\u0068\u0072\u006f\u0077\u0020\u006e\u0065\u0077\u0020\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0028\u0027\u0069\u0064\u0027\u002e\u0065\u0078\u0065\u0063\u0075\u0074\u0065\u0028\u0029\u002e\u0074\u0065\u0078\u0074\u0029\u003b`),
			},
			expectError: false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fmt.Printf("Running test: %s\n", test.description)
			res := backend_service.HttpResponse{}
			reg := prometheus.NewRegistry()
			metrics := CreateGoJaMetrics(reg)

			fdb := database.FakeDatabaseClient{}

			fRes := responder.FakeResponder{}
			jr := NewGojaJavascriptRunner(&fdb, []string{}, time.Minute, &fRes, metrics)

			// Ensure metadata is extracted from the request.
			eCol := extractors.NewExtractorCollection(true)
			eCol.ParseRequest(&test.request)

			err := jr.RunScript(test.script, test.request, &res, eCol, false)
			if (err != nil) != test.expectError {
				t.Errorf("got error: %s", err)
				return
			}

			if !test.expectError {
				metric := testutil.ToFloat64(metrics.javascriptSuccessCount.WithLabelValues(RunSuccess))
				if metric != 1 {
					t.Errorf("expected success metrics to be 1, got %f", metric)
				}
			}
		})
	}
}
