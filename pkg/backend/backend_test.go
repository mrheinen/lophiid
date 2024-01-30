package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/alerting"
	"loophid/pkg/database"
	"loophid/pkg/downloader"
	"loophid/pkg/javascript"
	"loophid/pkg/vt"
	"strings"
	"testing"
)

func TestGetMatchedRuleBasic(t *testing.T) {
	bunchOfRules := []database.ContentRule{
		{ID: 1, AppID: 1, Port: 80, Uri: "/42", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Port: 80, Uri: "/prefix", UriMatching: "prefix", ContentID: 43},
		{ID: 4, AppID: 3, Port: 80, Uri: "contains", UriMatching: "contains", ContentID: 44},
		{ID: 5, AppID: 4, Port: 80, Uri: "suffix", UriMatching: "suffix", ContentID: 45},
		{ID: 6, AppID: 4, Port: 80, Uri: "^/a[8-9/]*", UriMatching: "regex", ContentID: 46},
		{ID: 7, AppID: 7, Port: 443, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 8, AppID: 8, Port: 8888, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 9, AppID: 9, Port: 80, Body: "woohoo", BodyMatching: "exact", ContentID: 42},
		{ID: 10, AppID: 9, Port: 80, Body: "/etc/passwd", BodyMatching: "contains", ContentID: 42},
		{ID: 11, AppID: 9, Port: 80, Uri: "/pppaaattthhh", UriMatching: "exact", Body: "/etc/hosts", BodyMatching: "contains", ContentID: 42},
	}

	for _, test := range []struct {
		description           string
		requestInput          database.Request
		contentRulesInput     []database.ContentRule
		contentRuleIDExpected int64
		errorExpected         bool
	}{
		{
			description: "matched nothing ",
			requestInput: database.Request{
				Uri:  "/fddfffd",
				Port: 80,
			},
			contentRulesInput: bunchOfRules,
			errorExpected:     true,
		},
		{
			description: "matched one rule (exact) ",
			requestInput: database.Request{
				Uri:  "/42",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 1,
			errorExpected:         false,
		},
		{
			description: "matched one rule (prefix) ",
			requestInput: database.Request{
				Uri:  "/prefixdsfsfdf",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 3,
			errorExpected:         false,
		},

		{
			description: "matched one rule (contains) ",
			requestInput: database.Request{
				Uri:  "/sddsadcontainsfdfd",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 4,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: database.Request{
				Uri:  "/ttttt?aa=suffix",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 5,
			errorExpected:         false,
		},
		{
			description: "matched one rule (regex) ",
			requestInput: database.Request{
				Uri:  "/a898989898",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 6,
			errorExpected:         false,
		},
		{
			description: "matched one rule (on port) ",
			requestInput: database.Request{
				Uri:  "/eeee",
				Port: 8888,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 8,
			errorExpected:         false,
		},
		{
			description: "matched on body alone (exact) ",
			requestInput: database.Request{
				Uri:  "/eeee",
				Port: 80,
				Body: []byte("woohoo"),
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 9,
			errorExpected:         false,
		},
		{
			description: "matched on body alone (contains) ",
			requestInput: database.Request{
				Uri:  "/eeee",
				Port: 80,
				Body: []byte("asdssad /etc/passwd sdds"),
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 10,
			errorExpected:         false,
		},
		{
			description: "matched on body and path (contains) ",
			requestInput: database.Request{
				Uri:  "/pppaaattthhh",
				Port: 80,
				Body: []byte("asdssad /etc/hosts sdds"),
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 11,
			errorExpected:         false,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("Running: %s\n", test.description)

			fdbc := &database.FakeDatabaseClient{}
			fakeDownLoader := downloader.FakeDownloader{}
			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})

			matchedRule, err := b.GetMatchedRule(test.contentRulesInput, &test.requestInput)
			if (err != nil) != test.errorExpected {
				t.Errorf("error expected is: %t, but for err=%s", test.errorExpected, err)
			}

			if matchedRule.ID != test.contentRuleIDExpected {
				t.Errorf("expected %d but got %d", test.contentRuleIDExpected, matchedRule.ID)
			}
		})
	}
}

func TestGetMatchedRuleSameApp(t *testing.T) {
	bunchOfRules := []database.ContentRule{
		{ID: 1, AppID: 1, Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42},
		{ID: 2, AppID: 1, Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
	}

	fdbc := &database.FakeDatabaseClient{}
	fakeDownLoader := downloader.FakeDownloader{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})

	matchedRule, _ := b.GetMatchedRule(bunchOfRules, &database.Request{
		Uri:  "/aa",
		Port: 80,
	})

	if matchedRule.ID != 1 {
		t.Errorf("expected 1 but got %d", matchedRule.ID)
	}

	// The path of the next request matches two rules. We expect rule 2 to be
	// served though because it shares the app ID of the rule that was already
	// served.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &database.Request{
		Uri:  "/bb",
		Port: 80,
	})

	if matchedRule.ID != 2 {
		t.Errorf("expected 2 but got %d", matchedRule.ID)
	}

	// Again this matches two rules. However one of them is already served once
	// and this is kept track off. Therefore we expect the rule that was not
	// served before.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &database.Request{
		Uri:  "/bb",
		Port: 80,
	})

	if matchedRule.ID != 3 {
		t.Errorf("expected 3 but got %d", matchedRule.ID)
	}
}

func TestProbeRequestToDatabaseRequest(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeDownLoader := downloader.FakeDownloader{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})
	probeReq := backend_service.HandleProbeRequest{
		RequestUri: "/aa",
		Request: &backend_service.HttpRequest{
			Proto:         "HTTP/1.0",
			Method:        "GET",
			HoneypotIp:    "1.1.1.1",
			Body:          []byte("body"),
			RemoteAddress: "2.2.2.2:1337",
			ParsedUrl: &backend_service.ParsedURL{
				Port: 80,
				Path: "/aa",
			},
			Header: []*backend_service.KeyValue{
				{
					Key:   "referer",
					Value: "http://something",
				},
			},
		},
	}

	req, err := b.ProbeRequestToDatabaseRequest(&probeReq)
	if err != nil {
		t.Errorf("unexpected error %s", err)
	}

	if req.SourceIP != "2.2.2.2" {
		t.Errorf("expected 2.2.2.2 but got %s", req.SourceIP)
	}
}

func TestHandleProbe(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		RequestsToReturn: []database.Request{},
		ContentsToReturn: map[int64]database.Content{
			42: {
				ID:   42,
				Data: []byte("content data"),
			},
			43: {
				ID:   43,
				Data: []byte("some other data"),
			},
			44: {
				ID:     43,
				Data:   []byte(""),
				Script: "1+1",
			},
			66: {
				ID:   66,
				Data: []byte("default"),
			},
		},
		ContentRulesToReturn: []database.ContentRule{
			{ID: 1, AppID: 1, Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42},
			{ID: 2, AppID: 1, Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42},
			{ID: 3, AppID: 1, Port: 80, Uri: "/script", UriMatching: "exact", ContentID: 44},
		},
	}

	fakeDownLoader := downloader.FakeDownloader{}
	fakeJrunner := javascript.FakeJavascriptRunner{
		StringToReturn: "this is script",
		ErrorToReturn:  nil,
	}
	alertManager := alerting.NewAlertManager(42)
	b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})
	b.Start()

	probeReq := backend_service.HandleProbeRequest{
		RequestUri: "/aa",
		Request: &backend_service.HttpRequest{
			Proto:         "HTTP/1.0",
			Method:        "GET",
			HoneypotIp:    "1.1.1.1",
			Body:          []byte("body"),
			RemoteAddress: "2.2.2.2:1337",
			ParsedUrl: &backend_service.ParsedURL{
				Port: 80,
				Path: "/aa",
			},
			Header: []*backend_service.KeyValue{
				{
					Key:   "referer",
					Value: "http://something",
				},
			},
		},
	}

	// Everything is OK and we match a rule that has a content and the content
	// data is as expected.
	res, err := b.HandleProbe(context.Background(), &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if !bytes.Equal(res.Response.Body, fdbc.ContentsToReturn[42].Data) {
		t.Errorf("got %s, expected %s", res.Response.Body, fdbc.ContentsToReturn[42].Data)
	}

	// Now we simulate a request where the content response is based on a script.
	probeReq.RequestUri = "/script"
	res, err = b.HandleProbe(context.Background(), &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if !bytes.Equal(res.Response.Body, []byte(fakeJrunner.StringToReturn)) {
		t.Errorf("got %s, expected %s", res.Response.Body, fakeJrunner.StringToReturn)
	}

	// Now we test the default content fetching. Set the path to something that
	// doesn't match any rule.
	fdbc.HoneypotToReturn = database.Honeypot{
		DefaultContentID: 66,
	}
	probeReq.RequestUri = "/dffsd"
	res, err = b.HandleProbe(context.Background(), &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	if !bytes.Equal(res.Response.Body, []byte("default")) {
		t.Errorf("got %s, expected %s", res.Response.Body, "default")
	}

	// Now we simulate a database error. Should never occur ;p
	fdbc.ContentsToReturn = map[int64]database.Content{}
	res, err = b.HandleProbe(context.Background(), &probeReq)
	if res != nil || err == nil {
		t.Errorf("Expected error but got none: %v %s", res, err)
	}
}

func TestProcessQueue(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	fakeDownLoader := downloader.FakeDownloader{}
	alertManager := alerting.NewAlertManager(42)
	b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})
	req := database.Request{
		Uri:  "/aaaaa",
		Body: []byte("body body"),
		Raw:  "nothing",
	}

	b.reqsQueue.Push(&req)
	err := b.ProcessReqsQueue()
	if err != nil {
		t.Errorf("got error: %s", err)
	}

}

func TestSendStatus(t *testing.T) {

	for _, test := range []struct {
		description         string
		getHoneypotRet      database.Honeypot
		getHoneypotError    error
		request             *backend_service.StatusRequest
		expectedErrorString string
		dbErrorToReturn     error
	}{
		{
			description:      "inserts new honeypot",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: errors.New("boo"),
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip: "1.1.1.1",
			},
			expectedErrorString: "",
		},
		{
			description:      "inserts new honeypot fails",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: errors.New("boo"),
			dbErrorToReturn:  errors.New("oh oh"),
			request: &backend_service.StatusRequest{
				Ip: "1.1.1.1",
			},
			expectedErrorString: "error inserting honeypot",
		},
		{
			description:      "updates honeypot fails",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  errors.New("oh oh"),
			request: &backend_service.StatusRequest{
				Ip: "1.1.1.1",
			},
			expectedErrorString: "error updating honeypot",
		},
		{
			description:      "updates honeypot success",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip: "1.1.1.1",
			},
			expectedErrorString: "",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fmt.Printf("Running: %s\n", test.description)

			fdbc := &database.FakeDatabaseClient{
				HoneypotToReturn:      test.getHoneypotRet,
				HoneypotErrorToReturn: test.getHoneypotError,
				ErrorToReturn:         test.dbErrorToReturn,
			}

			fakeDownLoader := downloader.FakeDownloader{}
			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			b := NewBackendServer(fdbc, &fakeDownLoader, &fakeJrunner, alertManager, &vt.FakeVTManager{})

			_, err := b.SendStatus(context.Background(), test.request)
			if err == nil && test.expectedErrorString != "" {
				t.Errorf("expected error, got none")
			}

			if err != nil && !strings.Contains(err.Error(), test.expectedErrorString) {
				t.Errorf("expected error \"%s\", to contain \"%s\"", err, test.expectedErrorString)
			}

		})
	}
}
