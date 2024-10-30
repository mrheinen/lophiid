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
package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"lophiid/backend_service"
	"lophiid/pkg/alerting"
	"lophiid/pkg/analysis"
	"lophiid/pkg/backend/auth"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/backend/ratelimit"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/backend/session"
	"lophiid/pkg/database"
	"lophiid/pkg/javascript"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/vt"
	"lophiid/pkg/whois"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vingarcia/ksql"
)

func GetContextWithAuthMetadata() context.Context {
	return context.WithValue(context.WithoutCancel(context.Background()), auth.HoneypotMDKey{}, auth.HoneypotMetadata{})
}

func GetDefaultBackendConfig() Config {
	cfg := Config{}
	cfg.Backend.Advanced.ContentCacheDuration = time.Minute * 5
	cfg.Backend.Advanced.DownloadCacheDuration = time.Minute * 5
	cfg.Backend.Advanced.RequestsQueueSize = 100
	return cfg
}

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
			fdbc := &database.FakeDatabaseClient{}
			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeRdapManager{}
			queryRunner := FakeQueryRunner{
				ErrorToReturn: nil,
			}

			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)
			fakeLimiter := ratelimit.FakeRateLimiter{
				BoolToReturn:  true,
				ErrorToReturn: nil,
			}

			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{}
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

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
	whoisManager := whois.FakeRdapManager{}

	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}

	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

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
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())
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

func TestMaybeExtractLinksFromPayload(t *testing.T) {

	for _, test := range []struct {
		description      string
		content          []byte
		dInfo            database.Download
		expectedReturn   bool
		expectedSchedule bool
	}{
		{
			description: "does not schedule",
			content:     []byte("http://example.org"),
			dInfo: database.Download{
				ContentType:         "text/html",
				DetectedContentType: "text/html",
			},
			expectedReturn:   false,
			expectedSchedule: false,
		},
		{
			description: "does schedule",
			content:     []byte("http://example.org"),
			dInfo: database.Download{
				ContentType:         "text/x-sh",
				DetectedContentType: "text/html",
				Host:                "example.org:8000",
			},
			expectedReturn:   true,
			expectedSchedule: true,
		},
		{
			description: "does not schedule, exceeds limit",
			content:     []byte("http://example.org/1 http://example.org/2 http://example.org/3 http://example.org/4 http://example.org/5 http://example.org/6 http://example.org/7 http://example.org/8 http://example.org/9 http://example.org/10 http://example.org/11 http://example.org/12 http://example.org/13 http://example.org/14 http://example.org/15 http://example.org/16"),
			dInfo: database.Download{
				ContentType:         "text/x-sh",
				DetectedContentType: "text/html",
				Host:                "example.org:8000",
			},
			expectedReturn:   false,
			expectedSchedule: false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fdbc := &database.FakeDatabaseClient{}
			fakeJrunner := javascript.FakeJavascriptRunner{}
			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeRdapManager{}
			queryRunner := FakeQueryRunner{
				ErrorToReturn: nil,
			}
			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)

			fakeLimiter := ratelimit.FakeRateLimiter{
				BoolToReturn:  true,
				ErrorToReturn: nil,
			}
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{}
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

			if b.MaybeExtractLinksFromPayload(test.content, test.dInfo) != test.expectedReturn {
				t.Errorf("expected return %t but got %t", test.expectedReturn, !test.expectedReturn)
			}

			gotScheduled := len(b.downloadQueue) > 0
			if gotScheduled != test.expectedSchedule {
				t.Errorf("expected schedule %t but got %t", test.expectedSchedule, gotScheduled)
			}

		})
	}
}

// Test ScheduleDownloadOfPayload
func TestScheduleDownloadOfPayload(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

	ret := b.ScheduleDownloadOfPayload("1.1.1.1", "http://example.org", "2.2.2.2", "http://4.4.4.4", "example.org", 42)
	if ret != true {
		t.Errorf("expected true but got %t", ret)
	}
	ret = b.ScheduleDownloadOfPayload("1.1.1.1", "http://example.org", "2.2.2.2", "http://4.4.4.4", "example.org", 42)
	if ret != false {
		t.Errorf("expected false but got %t", ret)
	}
}

func TestHasParseableContent(t *testing.T) {
	for _, test := range []struct {
		description string
		url         string
		mime        string
		isParseable bool
	}{
		{
			description: "shell script",
			url:         "http://1.1.1.1/test.sh",
			mime:        "text/x-sh",
			isParseable: true,
		},
		{
			description: "shell script with different mime",
			url:         "http://1.1.1.1/test.sh",
			mime:        "text/html",
			isParseable: true,
		},
		{
			description: "shell script with no extension, right mime",
			url:         "http://1.1.1.1/test",
			mime:        "text/x-sh",
			isParseable: true,
		},
		{
			description: "shell script with no extension, right mime with encoding",
			url:         "http://1.1.1.1/test",
			mime:        "text/x-sh; charset=utf-8",
			isParseable: true,
		},
		{
			description: "shell script with parameter, wrong mime",
			url:         "http://1.1.1.1/test.sh?2332",
			mime:        "text/html",
			isParseable: true,
		},
		{
			description: "html page is ignored",
			url:         "http://1.1.1.1/test.html",
			mime:        "text/html",
			isParseable: false,
		},
		{
			description: "unparseable url",
			url:         "%%%%%%%%",
			mime:        "text/x-sh",
			isParseable: false,
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			if HasParseableContent(test.url, test.mime) != test.isParseable {
				t.Errorf("expected %t but got %t", test.isParseable, !test.isParseable)
			}
		})
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
				ID:      66,
				Data:    []byte("default"),
				Headers: pgtype.FlatArray[string]{"X-IP: 1.1.1.1"},
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
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}

	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())
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
	ctx := GetContextWithAuthMetadata()
	res, err := b.HandleProbe(ctx, &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	if !bytes.Equal(res.Response.Body, fdbc.ContentsToReturn[42].Data) {
		t.Errorf("got %s, expected %s", res.Response.Body, fdbc.ContentsToReturn[42].Data)
	}

	// Now we simulate a request where the content response is based on a script.
	probeReq.RequestUri = "/script"
	_, err = b.HandleProbe(ctx, &probeReq)
	if err != nil {
		t.Errorf("got error: %s", err)
	}

	// Now we test the default content fetching. Set the path to something that
	// doesn't match any rule.
	fdbc.HoneypotToReturn = database.Honeypot{
		DefaultContentID: 66,
	}
	probeReq.RequestUri = "/dffsd"
	res, err = b.HandleProbe(ctx, &probeReq)
	if err != nil {
		t.Fatalf("got error: %s", err)
	}
	if !bytes.Equal(res.Response.Body, []byte("default")) {
		t.Errorf("got %s, expected %s", res.Response.Body, "default")
	}

	if len(res.Response.Header) != 3 {
		t.Errorf("got %d, expected 3", len(res.Response.Header))
	}

	// Now we simulate a database error. Should never occur ;p
	fdbc.ContentsToReturn = map[int64]database.Content{}
	res, err = b.HandleProbe(ctx, &probeReq)
	if res != nil || err == nil {
		t.Errorf("Expected error but got none: %v %s", res, err)
	}

	// Call the method one more time but this time with a context that has
	// no metadata.
	_, err = b.HandleProbe(context.Background(), &probeReq)
	if err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("Expected error but got none")
	}

	fakeLimiter.BoolToReturn = false
	fakeLimiter.ErrorToReturn = errors.New("w00p w00p")

	_, err = b.HandleProbe(ctx, &probeReq)
	if err == nil || !strings.Contains(err.Error(), "w00p") {
		t.Errorf("Expected error but got none")
	}

	if len(fIpMgr.Events) != 1 {
		t.Fatalf("expected 1 AddEventTimes call, got %d", len(fIpMgr.Events))
	}

	if fIpMgr.Events[0].Type != constants.IpEventRateLimited {
		t.Fatalf("expected rate limited event, got %s", fIpMgr.Events[0].Type)
	}
}

func TestProcessQueue(t *testing.T) {
	for _, test := range []struct {
		description       string
		requestPurpose    string
		expectedEventType string
		ruleID            int
	}{
		{
			description:       "Runs ok, marked attack",
			requestPurpose:    database.RuleRequestPurposeAttack,
			expectedEventType: constants.IpEventAttacked,
			ruleID:            42,
		},
		{
			description:       "Runs ok, marked crawl",
			requestPurpose:    database.RuleRequestPurposeCrawl,
			expectedEventType: constants.IpEventCrawl,
			ruleID:            43,
		},
		{
			description:       "Runs ok, marked recon",
			requestPurpose:    database.RuleRequestPurposeRecon,
			expectedEventType: constants.IpEventRecon,
			ruleID:            44,
		},
	} {

		fdbc := &database.FakeDatabaseClient{}
		fakeJrunner := javascript.FakeJavascriptRunner{}
		alertManager := alerting.NewAlertManager(42)
		whoisManager := whois.FakeRdapManager{}
		queryRunner := FakeQueryRunner{
			ErrorToReturn: nil,
		}
		reg := prometheus.NewRegistry()
		bMetrics := CreateBackendMetrics(reg)

		fakeLimiter := ratelimit.FakeRateLimiter{
			BoolToReturn:  true,
			ErrorToReturn: nil,
		}
		fIpMgr := analysis.FakeIpEventManager{}
		fakeRes := &responder.FakeResponder{}
		fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
		b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())
		req := database.Request{
			ID:   42,
			Uri:  "/aaaaa",
			Body: []byte("body body"),
			Raw:  "nothing",
		}

		t.Run(test.description, func(t *testing.T) {

			eCol := extractors.NewExtractorCollection(true)
			err := b.ProcessRequest(&req, database.ContentRule{
				ID:             int64(test.ruleID),
				RequestPurpose: test.requestPurpose,
			}, eCol)

			if err != nil {
				t.Fatalf("got error: %s", err)
			}

			if len(fIpMgr.Events) != 1 {
				t.Fatalf("expected 1 AddEventTimes call, got %d", len(fIpMgr.Events))
			}

			if fIpMgr.Events[0].Type != test.expectedEventType {
				t.Errorf("expected %s, got %s", test.expectedEventType, fIpMgr.Events[0].Type)
			}

			if fIpMgr.Events[0].SourceRef != fmt.Sprintf("%d", test.ruleID) {
				t.Errorf("expected %d in %s", test.ruleID, fIpMgr.Events[0].Details)
			}

			if fIpMgr.Events[0].Source != constants.IpEventSourceRule {
				t.Errorf("expected %s, got %s", constants.IpEventSourceRule, fIpMgr.Events[0].Source)
			}
		})
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
			getHoneypotError: nil,
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:      "1.1.1.1",
				Version: constants.LophiidVersion,
			},
			expectedErrorString: "",
		},
		{
			description:      "inserts new honeypot fails on query",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: errors.New("boo"),
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:      "1.1.1.1",
				Version: constants.LophiidVersion,
			},
			expectedErrorString: "error doing lookup",
		},
		{
			description:      "inserts new honeypot fails on db",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  errors.New("foooo"),
			request: &backend_service.StatusRequest{
				Ip:      "1.1.1.1",
				Version: constants.LophiidVersion,
			},
			expectedErrorString: "error updating",
		},
		{
			description:      "updates honeypot fails on db",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  errors.New("oh oh"),
			request: &backend_service.StatusRequest{
				Ip:      "1.1.1.1",
				Version: constants.LophiidVersion,
			},
			expectedErrorString: "error updating honeypot",
		},
		{
			description:      "updates honeypot success",
			getHoneypotRet:   database.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:      "1.1.1.1",
				Version: constants.LophiidVersion,
			},
			expectedErrorString: "",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fdbc := &database.FakeDatabaseClient{
				HoneypotToReturn:      test.getHoneypotRet,
				HoneypotErrorToReturn: test.getHoneypotError,
				ErrorToReturn:         test.dbErrorToReturn,
			}

			fakeJrunner := javascript.FakeJavascriptRunner{}

			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeRdapManager{}
			queryRunner := FakeQueryRunner{
				ErrorToReturn: nil,
			}
			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)

			fakeLimiter := ratelimit.FakeRateLimiter{
				BoolToReturn:  true,
				ErrorToReturn: nil,
			}
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{}
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

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
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}

	testHoneypotIP := "1.1.1.1"
	testUrl := "http://test"

	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}

	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

	statusRequest := backend_service.StatusRequest{
		Ip:      testHoneypotIP,
		Version: constants.LophiidVersion,
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
				ID:                   41,
				TimesSeen:            1,
				VTAnalysisMalicious:  1,
				VTAnalysisSuspicious: 0,
			},
		},
	}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

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

	ctx := GetContextWithAuthMetadata()
	_, err := b.HandleUploadFile(ctx, &uploadRequest)
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

	if len(fIpMgr.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(fIpMgr.Events))
	}
}

func TestHandleP0fResult(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		P0fResultToReturn: database.P0fResult{},
		ErrorToReturn:     nil,
	}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, GetDefaultBackendConfig())

	// Insert a generic one. Should succeed
	fdbc.P0fErrorToReturn = ksql.ErrRecordNotFound
	hasInserted, err := b.HandleP0fResult("1.1.1.1", &backend_service.P0FResult{})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if hasInserted != true {
		t.Errorf("p0f result not inserted")
	}

	// Insert again but let the database return a fresh
	// result. Therefore the p0f result is no inserted in the database.
	fdbc.P0fResultToReturn = database.P0fResult{
		CreatedAt: time.Now(),
	}
	fdbc.P0fErrorToReturn = nil

	hasInserted, err = b.HandleP0fResult("1.1.1.1", &backend_service.P0FResult{})
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	if hasInserted != false {
		t.Errorf("p0f result was inserted")
	}
}

func TestGetResponderDataCases(t *testing.T) {

	fdbc := &database.FakeDatabaseClient{
		P0fResultToReturn: database.P0fResult{},
		ErrorToReturn:     nil,
	}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{
		ErrorToReturn: nil,
	}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour)

	for _, test := range []struct {
		description      string
		rule             database.ContentRule
		request          database.Request
		content          database.Content
		responder        *responder.FakeResponder
		lastPromptInput  string
		templateToReturn string
		expectedReturn   string
	}{
		{
			description: "work ok, NONE decoder",
			rule: database.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "([0-9]+)",
				ResponderDecoder: constants.ResponderDecoderTypeNone,
			},
			request: database.Request{
				Raw: "aa 898989",
			},
			content: database.Content{
				Data: []byte("not relevant"),
			},
			responder: &responder.FakeResponder{
				TemplateToReturn: "this is it",
				ErrorToReturn:    nil,
			},
			expectedReturn:  "this is it",
			lastPromptInput: "898989",
		},
		{
			description: "work ok, unknown decoder",
			rule: database.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "([0-9]+)",
				ResponderDecoder: "DOESNOTEXIST",
			},
			request: database.Request{
				Raw: "aa 898989",
			},
			content: database.Content{
				Data: []byte("this should be returned"),
			},
			responder: &responder.FakeResponder{
				TemplateToReturn: "this is it",
				ErrorToReturn:    nil,
			},
			expectedReturn:  "this should be returned",
			lastPromptInput: "",
		},
		{
			description: "work ok, URI decoder",
			rule: database.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "foo=([0-9a-f%]+)",
				ResponderDecoder: constants.ResponderDecoderTypeUri,
			},
			request: database.Request{
				Raw: "foo=%2e%2e%2e%41%41",
			},
			content: database.Content{
				Data: []byte("not relevant"),
			},
			responder: &responder.FakeResponder{
				TemplateToReturn: "this is it",
				ErrorToReturn:    nil,
			},
			expectedReturn:  "this is it",
			lastPromptInput: "...AA",
		},
		{
			description: "work ok, HTML decoder",
			rule: database.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "foo=([&a-z;]+)",
				ResponderDecoder: constants.ResponderDecoderTypeHtml,
			},
			request: database.Request{
				Raw: "foo=&gt;&lt;",
			},
			content: database.Content{
				Data: []byte("not relevant"),
			},
			responder: &responder.FakeResponder{
				TemplateToReturn: "this is it",
				ErrorToReturn:    nil,
			},
			expectedReturn:  "this is it",
			lastPromptInput: "><",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, test.responder, fSessionMgr, GetDefaultBackendConfig())
			ret := b.getResponderData(&test.request, &test.rule, &test.content)

			if ret != test.expectedReturn {
				t.Errorf("unexpected responder data, expected %s got %s", test.expectedReturn, ret)
			}

			if test.responder != nil && test.lastPromptInput != test.responder.LastPromptInput {
				t.Errorf("expected last prompt input %s but got %s", test.lastPromptInput, test.responder.LastPromptInput)
			}
		})
	}
}
