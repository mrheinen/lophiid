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
package responder

import (
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestInputLength(t *testing.T) {
	res := NewLLMResponder(nil, 50)
	randomString := util.GenerateRandomAlphaNumericString(51)

	_, err := res.Respond("", randomString, "")
	if err == nil {
		t.Errorf("expected error")
	}

	if err.Error() != "input too long (size: 51)" {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestUnknownResponder(t *testing.T) {

	res := NewLLMResponder(nil, 50)
	_, err := res.Respond("FOO", "", "")
	if err == nil {
		t.Errorf("expected error")
	}

	if err.Error() != "invalid responder type: FOO" {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestCommandInjection(t *testing.T) {

	for _, test := range []struct {
		description         string
		template            string
		completionToReturn  string
		expectedReturnValue string
		commandPrompt       string
	}{
		{
			description:         "works with single completion",
			completionToReturn:  "patrick",
			template:            "this is",
			expectedReturnValue: "this is\npatrick",
			commandPrompt:       "foo",
		},
		{
			description:         "works with single completion",
			completionToReturn:  "patrick",
			template:            "this is",
			expectedReturnValue: "this is\npatrickpatrick",
			commandPrompt:       "foo;bar",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			lmClient := llm.MockLLMClient{
				CompletionToReturn: test.completionToReturn,
				ErrorToReturn:      nil,
			}

			reg := prometheus.NewRegistry()
			metrics := llm.CreateLLMMetrics(reg)
			cache := util.NewStringMapCache[string]("foo", time.Minute)
			lm := llm.NewLLMManager(&lmClient, cache, metrics, time.Minute, 5, true, "", "")

			responder := NewLLMResponder(lm, 50)
			ret, err := responder.Respond(constants.ResponderTypeCommandInjection, test.commandPrompt, test.template)

			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if ret != test.expectedReturnValue {
				t.Errorf("unexpected result: %+#v", ret)
			}
		})
	}
}
