package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"loophid/backend_service"
	"loophid/pkg/alerting"
	"loophid/pkg/database"
	"loophid/pkg/javascript"
	"loophid/pkg/vt"
	"loophid/pkg/whois"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
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
			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeWhoisManager{}
			queryRunner := FakeQueryRunner{
				ErrorToReturn: nil,
			}

			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")

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
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}

	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")
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
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")
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

	fakeJrunner := javascript.FakeJavascriptRunner{
		ErrorToReturn: nil,
	}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")
	b.LoadRules()

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
	_, err = b.HandleProbe(context.Background(), &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
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
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")
	req := database.Request{
		Uri:  "/aaaaa",
		Body: []byte("body body"),
		Raw:  "nothing",
	}

	err := b.ProcessRequest(&req)
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

			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeWhoisManager{}
			queryRunner := FakeQueryRunner{
				ErrorToReturn: nil,
			}
			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")

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

func TestSendStatusSendsCommands(t *testing.T) {

	fdbc := &database.FakeDatabaseClient{
		HoneypotToReturn:      database.Honeypot{},
		HoneypotErrorToReturn: nil,
		ErrorToReturn:         nil,
	}

	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}

	testHoneypotIP := "1.1.1.1"
	testUrl := "http://test"

	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")

	statusRequest := backend_service.StatusRequest{
		Ip: testHoneypotIP,
	}

	b.downloadQueue[testHoneypotIP] = []backend_service.CommandDownloadFile{
		{
			Url: testUrl,
		},
	}

	resp, err := b.SendStatus(context.Background(), &statusRequest)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if len(resp.GetCommand()) != 1 {
		t.Errorf("expected 1 command. Got %d", len(resp.GetCommand()))
	}

	resUrl := resp.GetCommand()[0].GetDownloadCmd().Url
	if resUrl != testUrl {
		t.Errorf("expected %s, got %s", testUrl, resUrl)
	}
}

func TestHandleFileUploadUpdatesDownloadAndExtractsFromPayload(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		DownloadsToReturn: []database.Download{
			{
				ID:        41,
				TimesSeen: 1,
			},
		},
	}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeWhoisManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, "")

	uploadRequest := backend_service.UploadFileRequest{
		RequestId: 42,
		Info: &backend_service.DownloadInfo{
			HostHeader:  "example.org",
			ContentType: "text/html",
			HoneypotIp:  "1.1.1.1",
			OriginalUrl: "http://example.org/foo.sh",
			Url:         "http://127.0.0.1/foo.sh",
			Data:        []byte("extract this http://example.org/boo and ignore this http://www.google.com/foobar.sh"),
		},
	}

	_, err := b.HandleUploadFile(context.Background(), &uploadRequest)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if len(b.downloadQueue) != 1 {
		t.Errorf("expected len %d, got %d", 1, len(b.downloadQueue))
	}

	downloadEntry := fdbc.LastDataModelSeen.(*database.Download)
	if downloadEntry.TimesSeen != 2 {
		t.Errorf("expected times seen to be %d, got %d", 2, downloadEntry.TimesSeen)
	}
}
