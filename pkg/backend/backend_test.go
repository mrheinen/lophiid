package backend

import (
	"bytes"
	"context"
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/database"
	"loophid/pkg/downloader"
	"testing"
)

func TestGetMatchedRuleBasic(t *testing.T) {
	bunchOfRules := []database.ContentRule{
		{ID: 1, AppID: 1, Port: 80, Path: "/42", PathMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Port: 80, Path: "/prefix", PathMatching: "prefix", ContentID: 43},
		{ID: 4, AppID: 3, Port: 80, Path: "contains", PathMatching: "contains", ContentID: 44},
		{ID: 5, AppID: 4, Port: 80, Path: "suffix", PathMatching: "suffix", ContentID: 45},
		{ID: 6, AppID: 4, Port: 80, Path: "^/a[8-9/]*", PathMatching: "regex", ContentID: 46},
		{ID: 7, AppID: 7, Port: 443, Path: "/eeee", PathMatching: "exact", ContentID: 42},
		{ID: 8, AppID: 8, Port: 8888, Path: "/eeee", PathMatching: "exact", ContentID: 42},
		{ID: 9, AppID: 9, Port: 80, Body: "woohoo", BodyMatching: "exact", ContentID: 42},
		{ID: 10, AppID: 9, Port: 80, Body: "/etc/passwd", BodyMatching: "contains", ContentID: 42},
		{ID: 11, AppID: 9, Port: 80, Path: "/pppaaattthhh", PathMatching: "exact", Body: "/etc/hosts", BodyMatching: "contains", ContentID: 42},
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
				Path: "/fddfffd",
				Port: 80,
			},
			contentRulesInput: bunchOfRules,
			errorExpected:     true,
		},
		{
			description: "matched one rule (exact) ",
			requestInput: database.Request{
				Path: "/42",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 1,
			errorExpected:         false,
		},
		{
			description: "matched one rule (prefix) ",
			requestInput: database.Request{
				Path: "/prefixdsfsfdf",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 3,
			errorExpected:         false,
		},

		{
			description: "matched one rule (contains) ",
			requestInput: database.Request{
				Path: "/sddsadcontainsfdfd",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 4,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: database.Request{
				Path: "/ttttt?aa=suffix",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 5,
			errorExpected:         false,
		},
		{
			description: "matched one rule (regex) ",
			requestInput: database.Request{
				Path: "/a898989898",
				Port: 80,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 6,
			errorExpected:         false,
		},
		{
			description: "matched one rule (on port) ",
			requestInput: database.Request{
				Path: "/eeee",
				Port: 8888,
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 8,
			errorExpected:         false,
		},
		{
			description: "matched on body alone (exact) ",
			requestInput: database.Request{
				Path: "/eeee",
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
				Path: "/eeee",
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
				Path: "/pppaaattthhh",
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
			b := NewBackendServer(fdbc, &fakeDownLoader)

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
		{ID: 1, AppID: 1, Port: 80, Path: "/aa", PathMatching: "exact", ContentID: 42},
		{ID: 2, AppID: 1, Port: 80, Path: "/bb", PathMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Port: 80, Path: "/bb", PathMatching: "exact", ContentID: 42},
	}

	fdbc := &database.FakeDatabaseClient{}
	fakeDownLoader := downloader.FakeDownloader{}
	b := NewBackendServer(fdbc, &fakeDownLoader)

	matchedRule, _ := b.GetMatchedRule(bunchOfRules, &database.Request{
		Path: "/aa",
		Port: 80,
	})

	if matchedRule.ID != 1 {
		t.Errorf("expected 1 but got %d", matchedRule.ID)
	}

	// The path of the next request matches two rules. We expect rule 2 to be
	// served though because it shares the app ID of the rule that was already
	// served.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &database.Request{
		Path: "/bb",
		Port: 80,
	})

	if matchedRule.ID != 2 {
		t.Errorf("expected 2 but got %d", matchedRule.ID)
	}

	// Again this matches two rules. However one of them is already served once
	// and this is kept track off. Therefore we expect the rule that was not
	// served before.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &database.Request{
		Path: "/bb",
		Port: 80,
	})

	if matchedRule.ID != 3 {
		t.Errorf("expected 3 but got %d", matchedRule.ID)
	}
}

func TestProbeRequestToDatabaseRequest(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeDownLoader := downloader.FakeDownloader{}
	b := NewBackendServer(fdbc, &fakeDownLoader)

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
			42: database.Content{
				ID:   42,
				Data: []byte("content data"),
			},
			43: database.Content{
				ID:   43,
				Data: []byte("some other data"),
			},
		},
		ContentRulesToReturn: []database.ContentRule{
			{ID: 1, AppID: 1, Port: 80, Path: "/aa", PathMatching: "exact", ContentID: 42},
			{ID: 2, AppID: 1, Port: 80, Path: "/aa", PathMatching: "exact", ContentID: 42},
		},
	}

	fakeDownLoader := downloader.FakeDownloader{}
	b := NewBackendServer(fdbc, &fakeDownLoader)
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

	// Now we simulate a database error. Should never occur ;p
	fdbc.ContentsToReturn = map[int64]database.Content{}
	res, err = b.HandleProbe(context.Background(), &probeReq)
	if res != nil || err == nil {
		t.Errorf("Expected error but got none: %v %s", res, err)
	}
}

func TestProcessQueue(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeDownLoader := downloader.FakeDownloader{}
	b := NewBackendServer(fdbc, &fakeDownLoader)

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
