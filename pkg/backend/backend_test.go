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
	"lophiid/pkg/database/models"
	"lophiid/pkg/javascript"
	"lophiid/pkg/triage/describer"
	"lophiid/pkg/triage/preprocess"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"lophiid/pkg/vt"
	"lophiid/pkg/whois"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vingarcia/ksql"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestIsDebugIP(t *testing.T) {
	for _, test := range []struct {
		description string
		debugIPs    []string
		testIP      string
		expected    bool
	}{
		{
			description: "empty debug IPs list returns false",
			debugIPs:    []string{},
			testIP:      "192.168.1.1",
			expected:    false,
		},
		{
			description: "IP in debug list returns true",
			debugIPs:    []string{"10.0.0.1", "192.168.1.1", "172.16.0.1"},
			testIP:      "192.168.1.1",
			expected:    true,
		},
		{
			description: "IP not in debug list returns false",
			debugIPs:    []string{"10.0.0.1", "172.16.0.1"},
			testIP:      "192.168.1.1",
			expected:    false,
		},
		{
			description: "first IP in list matches",
			debugIPs:    []string{"192.168.1.1", "10.0.0.1"},
			testIP:      "192.168.1.1",
			expected:    true,
		},
		{
			description: "last IP in list matches",
			debugIPs:    []string{"10.0.0.1", "192.168.1.1"},
			testIP:      "192.168.1.1",
			expected:    true,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			cfg := GetDefaultBackendConfig()
			cfg.Backend.Advanced.DebugIPs = test.debugIPs

			bs := &BackendServer{config: cfg}
			result := bs.isDebugIP(test.testIP)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGetMatchedRuleBasic(t *testing.T) {
	bunchOfRules := []models.ContentRule{
		{ID: 1, AppID: 1, Method: "ANY", Ports: []int{80}, Uri: "/42", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Method: "GET", Ports: []int{80}, Uri: "/prefix", UriMatching: "prefix", ContentID: 43},
		{ID: 4, AppID: 3, Method: "GET", Ports: []int{80}, Uri: "contains", UriMatching: "contains", ContentID: 44},
		{ID: 5, AppID: 4, Method: "GET", Ports: []int{80}, Uri: "suffix", UriMatching: "suffix", ContentID: 45},
		{ID: 6, AppID: 4, Method: "GET", Ports: []int{80}, Uri: "^/a[8-9/]*", UriMatching: "regex", ContentID: 46},
		{ID: 7, AppID: 7, Method: "GET", Ports: []int{443}, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 8, AppID: 8, Method: "GET", Ports: []int{8888}, Uri: "/eeee", UriMatching: "exact", ContentID: 42},
		{ID: 9, AppID: 9, Method: "GET", Ports: []int{80}, Body: "woohoo", BodyMatching: "exact", ContentID: 42},
		{ID: 10, AppID: 9, Method: "GET", Ports: []int{80}, Body: "/etc/passwd", BodyMatching: "contains", ContentID: 42},
		{ID: 11, AppID: 9, Method: "GET", Ports: []int{80}, Uri: "/pppaaattthhh", UriMatching: "exact", Body: "/etc/hosts", BodyMatching: "contains", ContentID: 42},
		{ID: 12, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "suffix", UriMatching: "suffix", ContentID: 77},
		{ID: 13, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "/same", UriMatching: "exact", Body: "body", BodyMatching: "exact", ContentID: 77},
		{ID: 14, AppID: 4, Method: "POST", Ports: []int{80}, Uri: "/same", UriMatching: "exact", ContentID: 77},
	}

	for _, test := range []struct {
		description           string
		requestInput          models.Request
		contentRulesInput     []models.ContentRule
		contentRuleIDExpected int64
		errorExpected         bool
	}{
		{
			description: "matched nothing ",
			requestInput: models.Request{
				Uri:    "/fddfffd",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput: bunchOfRules,
			errorExpected:     true,
		},
		{
			description: "matched one rule (exact) ",
			requestInput: models.Request{
				Uri:    "/42",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 1,
			errorExpected:         false,
		},
		{
			description: "matched one rule (prefix) ",
			requestInput: models.Request{
				Uri:    "/prefixdsfsfdf",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 3,
			errorExpected:         false,
		},

		{
			description: "matched one rule (contains) ",
			requestInput: models.Request{
				Uri:    "/sddsadcontainsfdfd",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 4,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: models.Request{
				Uri:    "/ttttt?aa=suffix",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 5,
			errorExpected:         false,
		},
		{
			description: "matched one rule (suffix) ",
			requestInput: models.Request{
				Uri:    "/ttttt?aa=suffix",
				Port:   80,
				Method: "POST",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 12,
			errorExpected:         false,
		},

		{
			description: "matched one rule (regex) ",
			requestInput: models.Request{
				Uri:    "/a898989898",
				Port:   80,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 6,
			errorExpected:         false,
		},
		{
			description: "matched one rule (on port) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   8888,
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 8,
			errorExpected:         false,
		},
		{
			description: "matched one rule (uri and body)  ",
			requestInput: models.Request{
				Uri:    "/same",
				Port:   80,
				Body:   []byte("body"),
				Method: "POST",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 13,
			errorExpected:         false,
		},

		{
			description: "matched on body alone (exact) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   80,
				Body:   []byte("woohoo"),
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 9,
			errorExpected:         false,
		},

		{
			description: "matched on body alone (contains) ",
			requestInput: models.Request{
				Uri:    "/eeee",
				Port:   80,
				Body:   []byte("asdssad /etc/passwd sdds"),
				Method: "GET",
			},
			contentRulesInput:     bunchOfRules,
			contentRuleIDExpected: 10,
			errorExpected:         false,
		},
		{
			description: "matched on body and path (contains) ",
			requestInput: models.Request{
				Uri:    "/pppaaattthhh",
				Port:   80,
				Body:   []byte("asdssad /etc/hosts sdds"),
				Method: "GET",
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

			sMetrics := session.CreateSessionMetrics(reg)
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{}
			fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
			fakePreprocessor := preprocess.FakePreProcessor{}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

			matchedRule, err := b.GetMatchedRule(test.contentRulesInput, &test.requestInput, models.NewSession())
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
	bunchOfRules := []models.ContentRule{
		{ID: 1, AppID: 1, Method: "GET", Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42},
		{ID: 2, AppID: 1, Method: "GET", Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
		{ID: 3, AppID: 2, Method: "GET", Port: 80, Uri: "/bb", UriMatching: "exact", ContentID: 42},
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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

	fakePreprocessor := preprocess.FakePreProcessor{}
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

	myTestIP := "1.2.3.4"
	session, _ := b.sessionMgr.StartSession(myTestIP)
	matchedRule, _ := b.GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/aa",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	if matchedRule.ID != 1 {
		t.Errorf("expected 1 but got %d", matchedRule.ID)
	}

	// The path of the next request matches two rules. We expect rule 2 to be
	// served though because it shares the app ID of the rule that was already
	// served.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/bb",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	if matchedRule.ID != 2 {
		t.Errorf("expected 2 but got %d", matchedRule.ID)
	}

	// Again this matches two rules. However one of them is already served once
	// and this is kept track off. Therefore we expect the rule that was not
	// served before.
	matchedRule, _ = b.GetMatchedRule(bunchOfRules, &models.Request{
		Uri:      "/bb",
		Method:   "GET",
		Port:     80,
		SourceIP: myTestIP,
	}, session)

	if matchedRule.ID != 3 {
		t.Errorf("expected 3 but got %d", matchedRule.ID)
	}
}

func TestGetMatchedRulePortPrioritization(t *testing.T) {
	// Create test rules with and without ports
	rules := []models.ContentRule{
		{
			ID:          44,
			Uri:         "/test",
			Method:      "GET",
			UriMatching: "exact",
			AppID:       66,
		},
		{
			ID:          45,
			Uri:         "/test",
			Method:      "GET",
			Ports:       pgtype.FlatArray[int]{80, 443},
			UriMatching: "exact",
			AppID:       65,
		},
	}

	req := &models.Request{
		ID:       123,
		Method:   "GET",
		Uri:      "/test",
		SourceIP: "192.168.1.1",
		Port:     80,
	}

	// Create session and server
	sess := models.NewSession()

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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

	fakePreprocessor := preprocess.FakePreProcessor{}
	s := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

	// Test that rule with ports gets priority
	matchedRule, err := s.GetMatchedRule(rules, req, sess)
	if err != nil {
		t.Fatalf("GetMatchedRule returned error: %v", err)
	}
	if matchedRule.ID != 45 {
		t.Errorf("Expected rule with ports (ID 45) to be matched, got ID %d", matchedRule.ID)
	}

	// Mark rule with ports as served
	sess.ServedRuleWithContent(45, matchedRule.ContentID)

	// Test that rule without ports is selected when rule with ports is served
	matchedRule, err = s.GetMatchedRule(rules, req, sess)
	if err != nil {
		t.Fatalf("GetMatchedRule returned error: %v", err)
	}
	if matchedRule.ID != 44 {
		t.Errorf("Expected rule without ports (ID 44) to be matched, got ID %d", matchedRule.ID)
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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

	fakePreprocessor := preprocess.FakePreProcessor{}
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

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
		dInfo            models.Download
		expectedReturn   bool
		expectedSchedule bool
	}{
		{
			description: "does not schedule",
			content:     []byte("http://example.org"),
			dInfo: models.Download{
				ContentType:         "text/html",
				DetectedContentType: "text/html",
			},
			expectedReturn:   false,
			expectedSchedule: false,
		},
		{
			description: "does schedule",
			content:     []byte("http://example.org"),
			dInfo: models.Download{
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
			dInfo: models.Download{
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

			sMetrics := session.CreateSessionMetrics(reg)
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
			fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

			fakePreprocessor := preprocess.FakePreProcessor{}
			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

	// Create a custom config with a lower MaxDownloadsPerIP for testing
	config := GetDefaultBackendConfig()
	config.Backend.Advanced.MaxDownloadsPerIP = 3

	fakePreprocessor := preprocess.FakePreProcessor{}
	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, config)

	sourceIP := "1.2.3.4"

	// Test 1: First download should succeed
	ret := b.ScheduleDownloadOfPayload(sourceIP, "1.1.1.1", "http://example.org", "2.2.2.2", "http://4.4.4.4", "example.org", 42)
	if ret != true {
		t.Errorf("expected true but got %t", ret)
	}

	// Test 2: Same URL should be rejected (already in cache)
	ret = b.ScheduleDownloadOfPayload(sourceIP, "1.1.1.1", "http://example.org", "2.2.2.2", "http://4.4.4.4", "example.org", 42)
	if ret != false {
		t.Errorf("expected false but got %t", ret)
	}

	// Test 3: Different URL from same IP should succeed (count = 2)
	ret = b.ScheduleDownloadOfPayload(sourceIP, "1.1.1.1", "http://example2.org", "2.2.2.2", "http://4.4.4.4", "example2.org", 43)
	if ret != true {
		t.Errorf("expected true but got %t", ret)
	}

	// Test 4: Another URL from same IP should succeed (count = 3)
	ret = b.ScheduleDownloadOfPayload(sourceIP, "1.1.1.1", "http://example3.org", "2.2.2.2", "http://4.4.4.4", "example3.org", 44)
	if ret != true {
		t.Errorf("expected true but got %t", ret)
	}

	// Test 5: One more URL from same IP should fail (count = 4, MaxDownloadsPerIP = 3)
	ret = b.ScheduleDownloadOfPayload(sourceIP, "1.1.1.1", "http://example5.org", "2.2.2.2", "http://4.4.4.4", "example5.org", 46)
	if ret != false {
		t.Errorf("expected false (IP over limit) but got %t", ret)
	}

	// Test 6: Different IP should succeed regardless of previous IP's limit
	differentIP := "5.6.7.8"
	ret = b.ScheduleDownloadOfPayload(differentIP, "1.1.1.1", "http://example6.org", "2.2.2.2", "http://4.4.4.4", "example6.org", 47)
	if ret != true {
		t.Errorf("expected true for different IP but got %t", ret)
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
		RequestsToReturn: []models.Request{},
		HoneypotToReturn: models.Honeypot{RuleGroupID: 1, DefaultContentID: 66},
		ContentsToReturn: map[int64]models.Content{
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
		RulesPerGroupJoinToReturn: []models.RulePerGroupJoin{
			{Rule: models.ContentRule{ID: 1, AppID: 42, Block: false, Method: "GET", Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42}, RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 1, GroupID: 1}},
			{Rule: models.ContentRule{ID: 2, AppID: 42, Block: false, Method: "GET", Port: 80, Uri: "/aa", UriMatching: "exact", ContentID: 42}, RulePerGroup: models.RulePerGroup{ID: 2, RuleID: 2, GroupID: 1}},
			{Rule: models.ContentRule{ID: 3, AppID: 1, Block: false, Method: "GET", Port: 80, Uri: "/script", UriMatching: "exact", ContentID: 44}, RulePerGroup: models.RulePerGroup{ID: 3, RuleID: 3, GroupID: 1}},
			{Rule: models.ContentRule{ID: 4, AppID: 5, Block: true, Method: "GET", Port: 80, Uri: "/blocked", UriMatching: "exact", ContentID: 42}, RulePerGroup: models.RulePerGroup{ID: 4, RuleID: 4, GroupID: 1}},
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

	testSessionId := int64(3454)
	testSession := models.NewSession()
	testSession.ID = testSessionId
	fSessionMgr := &session.FakeSessionManager{
		ErrorToReturn:   nil,
		SessionToReturn: *testSession,
	}

	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
	fakePreprocessor := preprocess.FakePreProcessor{}

	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())
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

	t.Run("Matches ok", func(t *testing.T) {
		probeReq.RequestUri = "/aa"
		res, err := b.HandleProbe(ctx, &probeReq)
		if err != nil {
			t.Errorf("got error: %s", err)
		}

		if res == nil {
			t.Fatalf("got nil result")
		}

		if res.Response == nil {
      t.Errorf("got nil Response")
    }

		if !bytes.Equal(res.Response.Body, fdbc.ContentsToReturn[42].Data) {
			t.Errorf("got %s, expected %s", res.Response.Body, fdbc.ContentsToReturn[42].Data)
		}

		regWrap := <-b.reqsQueue
		if regWrap.req.AppID != 42 {
			t.Errorf("got %d, expected %d", regWrap.req.AppID, 42)
		}
	})

	t.Run("Script ok", func(t *testing.T) {
		// Now we simulate a request where the content response is based on a script.
		probeReq.RequestUri = "/script"
		_, err := b.HandleProbe(ctx, &probeReq)
		if err != nil {
			t.Errorf("got error: %s", err)
		}

		regWrap := <-b.reqsQueue
		if regWrap.req.AppID != 1 {
			t.Errorf("got %d, expected %d", regWrap.req.AppID, 1)
		}
	})

	t.Run("Honeypot default", func(t *testing.T) {
		// Now we test the default content fetching. Set the path to something that
		// doesn't match any rule. The honeypot's DefaultContentID (66) is used.
		probeReq.RequestUri = "/dffsd"
		res, err := b.HandleProbe(ctx, &probeReq)
		if err != nil {
			t.Fatalf("got error: %s", err)
		}
		if !bytes.Equal(res.Response.Body, []byte("default")) {
			t.Errorf("got %s, expected %s", res.Response.Body, "default")
		}

		if len(res.Response.Header) != 3 {
			t.Errorf("got %d, expected 3", len(res.Response.Header))
		}

		// Here it's 0 because we serve the default content for this honeypot and
		// therefore do not have a rule to get the application from.
		regWrap := <-b.reqsQueue
		if regWrap.req.AppID != 0 {
			t.Errorf("got %d, expected %d", regWrap.req.AppID, 0)
		}

	})

	t.Run("Content headers are added to response", func(t *testing.T) {
		fdbc.ContentsToReturn[99] = models.Content{
			ID:          99,
			Data:        []byte("test data"),
			ContentType: "text/html",
			Server:      "TestServer",
			Headers:     pgtype.FlatArray[string]{"X-Custom-Header: custom-value", "X-Another: another-value"},
		}
		fdbc.RulesPerGroupJoinToReturn = append(fdbc.RulesPerGroupJoinToReturn, models.RulePerGroupJoin{
			Rule:         models.ContentRule{ID: 99, AppID: 42, Method: "GET", Port: 80, Uri: "/headers-test", UriMatching: "exact", ContentID: 99},
			RulePerGroup: models.RulePerGroup{ID: 99, RuleID: 99, GroupID: 1},
		})
		b.LoadRules()

		probeReq.RequestUri = "/headers-test"
		probeReq.Request.ParsedUrl.Path = "/headers-test"
		res, err := b.HandleProbe(ctx, &probeReq)
		require.NoError(t, err)

		// Convert header slice to map for easier assertion
		headerMap := make(map[string]string)
		for _, h := range res.Response.Header {
			headerMap[h.Key] = h.Value
		}

		assert.Equal(t, "custom-value", headerMap["X-Custom-Header"])
		assert.Equal(t, "another-value", headerMap["X-Another"])
		assert.Equal(t, "text/html", headerMap["Content-Type"])
		assert.Equal(t, "TestServer", headerMap["Server"])

		<-b.reqsQueue // drain
	})

	t.Run("database error", func(t *testing.T) {
		// Now we simulate a database error. Should never occur ;p
		fdbc.ContentsToReturn = map[int64]models.Content{}
		res, err := b.HandleProbe(ctx, &probeReq)
		if res != nil || err == nil {
			t.Errorf("Expected error but got none: %v %s", res, err)
		}

		// Call the method one more time but this time with a context that has
		// no metadata.
		_, err = b.HandleProbe(context.Background(), &probeReq)
		if err == nil || !strings.Contains(err.Error(), "auth") {
			t.Errorf("Expected error but got none")
		}
	})

	t.Run("limiter limits", func(t *testing.T) {
		fakeLimiter.BoolToReturn = false
		fakeLimiter.ErrorToReturn = errors.New("w00p w00p")

		_, err := b.HandleProbe(ctx, &probeReq)
		if err == nil || !strings.Contains(err.Error(), "w00p") {
			t.Errorf("Expected error but got none")
		}

		if len(fIpMgr.Events) != 1 {
			t.Fatalf("expected 1 AddEventTimes call, got %d", len(fIpMgr.Events))
		}

		if fIpMgr.Events[0].Type != constants.IpEventRateLimited {
			t.Fatalf("expected rate limited event, got %s", fIpMgr.Events[0].Type)
		}

		if fIpMgr.Events[0].SourceRefType != constants.IpEventRefTypeSessionId {
			t.Fatalf("expected session event, got %s", fIpMgr.Events[0].SourceRefType)
		}

		if fIpMgr.Events[0].SourceRef != fmt.Sprintf("%d", testSessionId) {
			t.Fatalf("expected %d, got %s", testSessionId, fIpMgr.Events[0].SourceRef)
		}
	})

	t.Run("rule blocks request", func(t *testing.T) {
		// Reset limiter for this test
		fakeLimiter.BoolToReturn = true
		fakeLimiter.ErrorToReturn = nil

		// Set request URI to match our blocking rule
		probeReq.RequestUri = "/blocked"
		probeReq.Request.ParsedUrl.Path = "/blocked"

		// Call HandleProbe and verify it returns a PermissionDenied error
		res, err := b.HandleProbe(ctx, &probeReq)

		// Check that we got the expected error
		if res != nil {
			t.Errorf("Expected nil response but got: %v", res)
		}

		if err == nil {
			t.Errorf("Expected error but got none")
		}

		// Check for the specific error code and message
		statusErr, ok := status.FromError(err)
		if !ok {
			t.Errorf("Expected gRPC status error but got: %v", err)
		}

		if statusErr.Code() != codes.PermissionDenied {
			t.Errorf("Expected PermissionDenied error but got: %v", statusErr.Code())
		}

		metric := testutil.ToFloat64(bMetrics.requestsBlocked)
		if metric != 1 {
			t.Errorf("Expected metric to be 1 but got: %f", metric)
		}

		if statusErr.Message() != "Rule blocks request" {
			t.Errorf("Expected 'Rule blocks request' in error message but got: %s", statusErr.Message())
		}

		// No request should be added to the queue for blocked requests
	})
}

// TestHandleProbePreprocessHeaders verifies that headers returned by the
// preprocessor are properly added to the final HTTP response.
func TestHandleProbePreprocessHeaders(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		HoneypotToReturn: models.Honeypot{RuleGroupID: 1},
		ContentsToReturn: map[int64]models.Content{
			100: {
				ID:   100,
				Data: []byte("preprocess content"),
			},
		},
		RulesPerGroupJoinToReturn: []models.RulePerGroupJoin{
			{Rule: models.ContentRule{ID: 100, AppID: 42, Method: "GET", Port: 80, Uri: "/preprocess-headers", UriMatching: "exact", ContentID: 100, Responder: constants.ResponderTypeAuto}, RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 100, GroupID: 1}},
		},
	}

	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fakeDescriber := describer.FakeDescriberClient{}
	fakePreprocessor := preprocess.FakePreProcessor{
		ResultToReturn: &preprocess.PreProcessResult{
			HasPayload:  true,
			PayloadType: "SQLI",
		},
		PayloadResult: &preprocess.PayloadProcessingResult{
			Output:  "injected output",
			Headers: "X-Preprocess: preprocess-value\nX-LLM-Generated: true",
		},
	}

	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())
	b.LoadRules()

	ctx := GetContextWithAuthMetadata()
	probeReq := &backend_service.HandleProbeRequest{
		RequestUri: "/preprocess-headers",
		Request: &backend_service.HttpRequest{
			Proto:         "HTTP/1.0",
			Method:        "GET",
			HoneypotIp:    "1.1.1.1",
			Body:          []byte("body"),
			RemoteAddress: "2.2.2.2:1337",
			ParsedUrl: &backend_service.ParsedURL{
				Port: 80,
				Path: "/preprocess-headers",
			},
		},
	}

	res, err := b.HandleProbe(ctx, probeReq)
	require.NoError(t, err)

	// Convert header slice to map for easier assertion
	headerMap := make(map[string]string)
	for _, h := range res.Response.Header {
		headerMap[h.Key] = h.Value
	}

	assert.Equal(t, "preprocess-value", headerMap["X-Preprocess"])
	assert.Equal(t, "true", headerMap["X-LLM-Generated"])

	<-b.reqsQueue // drain
}

func TestProcessQueue(t *testing.T) {
	for _, test := range []struct {
		description          string
		requestPurpose       string
		expectedEventType    string
		expectedEventSubType string
		ruleID               int
		request              *models.Request
		expectedPingCommand  *backend_service.CommandPingAddress
	}{
		{
			description:          "Runs ok, marked attack",
			requestPurpose:       models.RuleRequestPurposeAttack,
			expectedEventType:    constants.IpEventTrafficClass,
			expectedEventSubType: constants.IpEventSubTypeTrafficClassAttacked,
			ruleID:               42,
			request: &models.Request{
				ID:   42,
				Uri:  "/aaaaa",
				Body: []byte("body body"),
				Raw:  []byte("nothing"),
			},
		},
		{
			description:          "Runs ok, marked crawl",
			requestPurpose:       models.RuleRequestPurposeCrawl,
			expectedEventType:    constants.IpEventTrafficClass,
			expectedEventSubType: constants.IpEventSubTypeTrafficClassCrawl,
			ruleID:               43,
			request: &models.Request{
				ID:   42,
				Uri:  "/aaaaa",
				Body: []byte("body body"),
				Raw:  []byte("nothing"),
			},
		},
		{
			description:          "Runs ok, marked recon",
			requestPurpose:       models.RuleRequestPurposeRecon,
			expectedEventType:    constants.IpEventTrafficClass,
			expectedEventSubType: constants.IpEventSubTypeTrafficClassRecon,
			ruleID:               44,
			request: &models.Request{
				ID:   42,
				Uri:  "/aaaaa",
				Body: []byte("body body"),
				Raw:  []byte("nothing"),
			},
		},
		{
			description:          "Runs ok, marked attack, ping command",
			requestPurpose:       models.RuleRequestPurposeAttack,
			expectedEventType:    constants.IpEventTrafficClass,
			expectedEventSubType: constants.IpEventSubTypeTrafficClassAttacked,
			ruleID:               42,
			request: &models.Request{
				ID:         232,
				Uri:        "/aaaaa",
				Body:       []byte("body body ping -c 4 1.1.1.1 foo"),
				Raw:        []byte("nothing"),
				HoneypotIP: "4.4.4.4",
			},
			expectedPingCommand: &backend_service.CommandPingAddress{
				Address:   "1.1.1.1",
				Count:     4,
				RequestId: 232,
			},
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

		sMetrics := session.CreateSessionMetrics(reg)
		fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
		fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
		fakePreprocessor := preprocess.FakePreProcessor{}

		b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

		t.Run(test.description, func(t *testing.T) {

			eCol := extractors.NewExtractorCollection(true)
			eCol.ParseRequest(test.request)
			err := b.ProcessRequest(test.request, models.ContentRule{
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
			if fIpMgr.Events[0].Subtype != test.expectedEventSubType {
				t.Errorf("expected %s, got %s", test.expectedEventSubType, fIpMgr.Events[0].Subtype)
			}

			if fIpMgr.Events[0].SourceRef != fmt.Sprintf("%d", test.ruleID) {
				t.Errorf("expected %d in %s", test.ruleID, fIpMgr.Events[0].Details)
			}

			if fIpMgr.Events[0].Source != constants.IpEventSourceRule {
				t.Errorf("expected %s, got %s", constants.IpEventSourceRule, fIpMgr.Events[0].Source)
			}

			if test.expectedPingCommand != nil {
				c, ok := b.pingQueue[test.request.HoneypotIP]
				if !ok || len(c) == 0 {
					t.Fatalf("Ping command not found in queue")
				}

				if !reflect.DeepEqual(c[0], *test.expectedPingCommand) {
					t.Errorf("expected %v, got %v", test.expectedPingCommand, c[0])
				}
			}
		})
	}
}

func TestSendStatus(t *testing.T) {

	for _, test := range []struct {
		description         string
		getHoneypotRet      models.Honeypot
		getHoneypotError    error
		request             *backend_service.StatusRequest
		expectedErrorString string
		dbErrorToReturn     error
	}{
		{
			description:      "inserts new honeypot",
			getHoneypotRet:   models.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:            "1.1.1.1",
				Version:       constants.LophiidVersion,
				ListenPort:    []int64{80},
				ListenPortSsl: []int64{443},
			},
			expectedErrorString: "",
		},
		{
			description:      "inserts new honeypot fails on query",
			getHoneypotRet:   models.Honeypot{},
			getHoneypotError: errors.New("boo"),
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:            "1.1.1.1",
				Version:       constants.LophiidVersion,
				ListenPort:    []int64{80},
				ListenPortSsl: []int64{443},
			},
			expectedErrorString: "error doing lookup",
		},
		{
			description:      "inserts new honeypot fails on db",
			getHoneypotRet:   models.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  errors.New("foooo"),
			request: &backend_service.StatusRequest{
				Ip:            "1.1.1.1",
				Version:       constants.LophiidVersion,
				ListenPort:    []int64{80},
				ListenPortSsl: []int64{443},
			},
			expectedErrorString: "error updating",
		},
		{
			description:      "updates honeypot fails on db",
			getHoneypotRet:   models.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  errors.New("oh oh"),
			request: &backend_service.StatusRequest{
				Ip:            "1.1.1.1",
				Version:       constants.LophiidVersion,
				ListenPort:    []int64{80},
				ListenPortSsl: []int64{443},
			},
			expectedErrorString: "error updating honeypot",
		},
		{
			description:      "updates honeypot success",
			getHoneypotRet:   models.Honeypot{},
			getHoneypotError: nil,
			dbErrorToReturn:  nil,
			request: &backend_service.StatusRequest{
				Ip:            "1.1.1.1",
				Version:       constants.LophiidVersion,
				ListenPort:    []int64{80},
				ListenPortSsl: []int64{443},
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

			sMetrics := session.CreateSessionMetrics(reg)
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
			fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
			fakePreprocessor := preprocess.FakePreProcessor{}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

			_, err := b.SendStatus(context.Background(), test.request)
			if err == nil && test.expectedErrorString != "" {
				t.Errorf("expected error, got none")
			}

			if err != nil && !strings.Contains(err.Error(), test.expectedErrorString) {
				t.Errorf("expected error \"%s\", to contain \"%s\"", err, test.expectedErrorString)
			}

			if test.dbErrorToReturn != nil {
				lastDm := fdbc.LastDataModelSeen.(*models.Honeypot)

				if len(lastDm.SSLPorts) != len(test.request.ListenPortSsl) {
					t.Errorf("expected %d, got %d", len(test.request.ListenPortSsl), len(lastDm.SSLPorts))
				}

				if len(lastDm.Ports) != len(test.request.ListenPort) {
					t.Errorf("expected %d, got %d", len(test.request.ListenPort), len(lastDm.Ports))
				}

				if lastDm.SSLPorts[0] != test.request.ListenPortSsl[0] {
					t.Errorf("expected %d, got %d", test.request.ListenPortSsl[0], lastDm.SSLPorts[0])
				}

				if lastDm.Ports[0] != test.request.ListenPort[0] {
					t.Errorf("expected %d, got %d", test.request.ListenPort[0], lastDm.Ports[0])
				}
			}
		})
	}
}

func TestSendStatusSendsCommands(t *testing.T) {

	fdbc := &database.FakeDatabaseClient{
		HoneypotToReturn:      models.Honeypot{},
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

	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
	fakePreprocessor := preprocess.FakePreProcessor{}

	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

	statusRequest := backend_service.StatusRequest{
		Ip:      testHoneypotIP,
		Version: constants.LophiidVersion,
	}

	t.Run("SendStatus download command", func(t *testing.T) {
		testUrl := "http://test"
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
			t.Fatalf("expected 1 command. Got %d", len(resp.GetCommand()))
		}

		resUrl := resp.GetCommand()[0].GetDownloadCmd().Url
		if resUrl != testUrl {
			t.Errorf("expected %s, got %s", testUrl, resUrl)
		}
	})

	t.Run("SendStatus ping command", func(t *testing.T) {
		testAddress := "1.1.1.1"
		testCount := 12
		testReqId := 42

		b.pingQueue[testHoneypotIP] = []backend_service.CommandPingAddress{
			{
				Address:   testAddress,
				Count:     int64(testCount),
				RequestId: int64(testReqId),
			},
		}

		resp, err := b.SendStatus(context.Background(), &statusRequest)
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		if len(resp.GetCommand()) != 1 {
			t.Fatalf("expected 1 command. Got %d", len(resp.GetCommand()))
		}

		resAdd := resp.GetCommand()[0].GetPingCmd().Address
		if resAdd != testAddress {
			t.Errorf("expected %s, got %s", testAddress, resAdd)
		}

		if resp.GetCommand()[0].GetPingCmd().Count != int64(testCount) {
			t.Errorf("expected %d, got %d", testCount, resp.GetCommand()[0].GetPingCmd().Count)
		}

		if resp.GetCommand()[0].GetPingCmd().RequestId != int64(testReqId) {
			t.Errorf("expected %d, got %d", testReqId, resp.GetCommand()[0].GetPingCmd().RequestId)
		}
	})
}

func TestHandleFileUploadUpdatesDownloadAndExtractsFromPayload(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		DownloadsToReturn: []models.Download{
			{
				ID:                   41,
				TimesSeen:            1,
				VTAnalysisMalicious:  1,
				VTAnalysisSuspicious: 0,
				RawHttpResponse:      "old data",
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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
	fakePreprocessor := preprocess.FakePreProcessor{}

	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

	uploadRequest := backend_service.UploadFileRequest{
		RequestId: 42,
		Info: &backend_service.DownloadInfo{
			HostHeader:      "example.org",
			ContentType:     "text/html",
			HoneypotIp:      "1.1.1.1",
			OriginalUrl:     "http://example.org/foo.sh",
			Url:             "http://127.0.0.1/foo.sh",
			Data:            []byte("extract this http://example.org/boo and ignore this http://www.google.com/foobar.sh"),
			RawHttpResponse: "this is raw data",
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

	downloadEntry := fdbc.LastDataModelSeen.(*models.Download)
	if downloadEntry.TimesSeen != 2 {
		t.Errorf("expected times seen to be %d, got %d", 2, downloadEntry.TimesSeen)
	}

	if downloadEntry.RawHttpResponse != "this is raw data" {
		t.Errorf("expected raw response to be %s, got %s", "this is raw data", downloadEntry.RawHttpResponse)
	}

	if len(fIpMgr.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(fIpMgr.Events))
	}
}

func TestHandleP0fResult(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{
		P0fResultToReturn: models.P0fResult{},
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

	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)

	fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
	fakePreprocessor := preprocess.FakePreProcessor{}

	b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

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
	fdbc.P0fResultToReturn = models.P0fResult{
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
		P0fResultToReturn: models.P0fResult{},
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
	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)

	for _, test := range []struct {
		description      string
		rule             models.ContentRule
		request          models.Request
		content          models.Content
		responder        *responder.FakeResponder
		lastPromptInput  string
		templateToReturn string
		expectedReturn   string
	}{
		{
			description: "work ok, NONE decoder",
			rule: models.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "([0-9]+)",
				ResponderDecoder: constants.ResponderDecoderTypeNone,
			},
			request: models.Request{
				Raw: []byte("aa 898989"),
			},
			content: models.Content{
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
			rule: models.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "([0-9]+)",
				ResponderDecoder: "DOESNOTEXIST",
			},
			request: models.Request{
				Raw: []byte("aa 898989"),
			},
			content: models.Content{
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
			rule: models.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "foo=([0-9a-f%]+)",
				ResponderDecoder: constants.ResponderDecoderTypeUri,
			},
			request: models.Request{
				Raw: []byte("foo=%2e%2e%2e%41%41"),
			},
			content: models.Content{
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
			rule: models.ContentRule{
				Responder:        "COMMAND_INJECTION",
				ResponderRegex:   "foo=([&a-z;]+)",
				ResponderDecoder: constants.ResponderDecoderTypeHtml,
			},
			request: models.Request{
				Raw: []byte("foo=&gt;&lt;"),
			},
			content: models.Content{
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

			fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}
			fakePreprocessor := preprocess.FakePreProcessor{}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, test.responder, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())
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

func TestHandlePingStatus(t *testing.T) {

	fdbc := &database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{}
	fakeLimiter := ratelimit.FakeRateLimiter{}
	fSessionMgr := &session.FakeSessionManager{}
	fakeDescriber := describer.FakeDescriberClient{}

	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)

	fakeRes := &responder.FakeResponder{}

	for _, test := range []struct {
		description          string
		request              *backend_service.SendPingStatusRequest
		expectedEventSubType string
	}{
		{
			description:          "success event on success",
			expectedEventSubType: constants.IpEventSubTypeSuccess,
			request: &backend_service.SendPingStatusRequest{
				Address:         "1.1.1.1",
				Count:           5,
				PacketsSent:     5,
				PacketsReceived: 5,
				RequestId:       42,
			},
		},
		{
			description:          "failure event on count failure",
			expectedEventSubType: constants.IpEventSubTypeFailure,
			request: &backend_service.SendPingStatusRequest{
				Address:         "1.1.1.1",
				Count:           4,
				PacketsSent:     5,
				PacketsReceived: 5,
				RequestId:       42,
			},
		},
		{
			description:          "failure event on packets mismatch failure",
			expectedEventSubType: constants.IpEventSubTypeFailure,
			request: &backend_service.SendPingStatusRequest{
				Address:         "1.1.1.1",
				Count:           5,
				PacketsSent:     5,
				PacketsReceived: 4,
				RequestId:       42,
			},
		},
	} {

		t.Run(test.description, func(t *testing.T) {

			fIpMgr := analysis.FakeIpEventManager{}
			fakePreprocessor := preprocess.FakePreProcessor{}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())
			ctx := GetContextWithAuthMetadata()

			_, err := b.SendPingStatus(ctx, test.request)
			if err != nil {
				t.Errorf("got error: %s", err)
			}

			if len(fIpMgr.Events) != 1 {
				t.Errorf("expected 1, got %d", len(fIpMgr.Events))
			}

			if fIpMgr.Events[0].Subtype != test.expectedEventSubType {
				t.Errorf("expected %s, got %s", test.expectedEventSubType, fIpMgr.Events[0].Subtype)
			}
		})
	}
}

func TestHandleProbeResponderLogic(t *testing.T) {
	// Test the responder logic block from lines 1043-1061
	for _, test := range []struct {
		description       string
		responderType     string
		preprocessResult  *preprocess.PreProcessResult
		preprocessBody    string
		preprocessError   error
		responderResponse string
		responderRegex    string
		responderDecoder  string
		requestRaw        []byte
		contentData       []byte
		expectedBody      string
	}{
		{
			description:   "No responder - uses content data",
			responderType: "",
			contentData:   []byte("default content"),
			expectedBody:  "default content",
		},
		{
			description:   "ResponderTypeNone - uses content data",
			responderType: constants.ResponderTypeNone,
			contentData:   []byte("default content"),
			expectedBody:  "default content",
		},
		{
			description:   "ResponderTypeAuto success - uses preprocessed response",
			responderType: constants.ResponderTypeAuto,
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "SHELL_COMMAND",
				Payload:     "whoami",
			},
			preprocessBody:  "root",
			preprocessError: nil,
			contentData:     []byte("default content"),
			expectedBody:    "default content\nroot",
		},
		{
			description:      "ResponderTypeAuto with ErrNotProcessed - uses content data",
			responderType:    constants.ResponderTypeAuto,
			preprocessResult: nil,
			preprocessError:  preprocess.ErrNotProcessed,
			contentData:      []byte("default content"),
			expectedBody:     "default content",
		},
		{
			description:      "ResponderTypeAuto with other error - uses content data",
			responderType:    constants.ResponderTypeAuto,
			preprocessResult: nil,
			preprocessError:  errors.New("LLM service error"),
			contentData:      []byte("default content"),
			expectedBody:     "default content",
		},
		{
			description:       "ResponderTypeCommandInjection - uses responder data",
			responderType:     constants.ResponderTypeCommandInjection,
			responderResponse: "command response",
			responderRegex:    "cmd=([^&]+)",
			responderDecoder:  constants.ResponderDecoderTypeNone,
			requestRaw:        []byte("GET /test?cmd=whoami HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n"),
			contentData:       []byte("default content"),
			expectedBody:      "command response",
		},
		{
			description:       "Non-AUTO responder without capture - uses content data",
			responderType:     constants.ResponderTypeCommandInjection,
			responderResponse: "should not see this",
			responderRegex:    ".*",
			requestRaw:        []byte("GET /test HTTP/1.0\r\n\r\n"),
			contentData:       []byte("fallback content"),
			expectedBody:      "fallback content",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fdbc := &database.FakeDatabaseClient{
				HoneypotToReturn: models.Honeypot{RuleGroupID: 1},
				ContentsToReturn: map[int64]models.Content{
					42: {
						ID:   42,
						Data: test.contentData,
					},
				},
				RulesPerGroupJoinToReturn: []models.RulePerGroupJoin{
					{
						Rule: models.ContentRule{
							ID:               1,
							AppID:            1,
							Method:           "GET",
							Port:             80,
							Uri:              "/test",
							UriMatching:      "exact",
							ContentID:        42,
							Responder:        test.responderType,
							ResponderRegex:   test.responderRegex,
							ResponderDecoder: test.responderDecoder,
						},
						RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 1, GroupID: 1},
					},
				},
			}

			fakeJrunner := javascript.FakeJavascriptRunner{}
			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeRdapManager{}
			queryRunner := FakeQueryRunner{}
			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)
			fakeLimiter := ratelimit.FakeRateLimiter{
				BoolToReturn:  true,
				ErrorToReturn: nil,
			}
			sMetrics := session.CreateSessionMetrics(reg)
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{
				TemplateToReturn: test.responderResponse,
			}
			fakeDescriber := describer.FakeDescriberClient{}
			fakePreprocessor := preprocess.FakePreProcessor{
				ResultToReturn: func() *preprocess.PreProcessResult {
					if test.preprocessResult != nil {
						return test.preprocessResult
					}
					return &preprocess.PreProcessResult{}
				}(),
				PayloadResult: &preprocess.PayloadProcessingResult{Output: test.preprocessBody},
				ErrorToReturn: test.preprocessError,
			}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())
			b.LoadRules()

			ctx := GetContextWithAuthMetadata()
			probeReq := &backend_service.HandleProbeRequest{
				RequestUri: "/test",
				Request: &backend_service.HttpRequest{
					Proto:         "HTTP/1.0",
					Method:        "GET",
					HoneypotIp:    "1.1.1.1",
					Body:          []byte("test body"),
					RemoteAddress: "2.2.2.2:1337",
					Raw:           test.requestRaw,
					ParsedUrl: &backend_service.ParsedURL{
						Port: 80,
						Path: "/test",
					},
				},
			}

			res, err := b.HandleProbe(ctx, probeReq)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res == nil {
				t.Fatal("expected response, got nil")
			}

			if !bytes.Equal(res.Response.Body, []byte(test.expectedBody)) {
				t.Errorf("expected body '%s', got '%s'", test.expectedBody, string(res.Response.Body))
			}

			// Drain the queue
			<-b.reqsQueue
		})
	}
}

func TestGetPreProcessResponse(t *testing.T) {
	for _, test := range []struct {
		description       string
		filter            bool
		cmpHashInCache    bool
		preprocessResult  *preprocess.PreProcessResult
		preprocessBody    string
		preprocessError   error
		expectedError     bool
		expectedResponse  string
		expectedPayload   string
		expectedHasMarked bool
	}{
		{
			description: "success with filter=false",
			filter:      false,
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "SHELL_COMMAND",
				Payload:     "ls -la",
			},
			preprocessBody:    "response body",
			expectedError:     false,
			expectedResponse:  "response body",
			expectedPayload:   "ls -la",
			expectedHasMarked: true,
		},
		{
			description:    "success with filter=true and cache hit",
			filter:         true,
			cmpHashInCache: true,
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "FILE_ACCESS",
				Payload:     "/etc/passwd",
			},
			preprocessBody:    "file access response",
			expectedError:     false,
			expectedResponse:  "file access response",
			expectedPayload:   "/etc/passwd",
			expectedHasMarked: true,
		},
		{
			description:    "success with filter=true and cache miss",
			filter:         true,
			cmpHashInCache: false,
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "CODE_EXECUTION",
				Payload:     "<?php echo 'test'; ?>",
			},
			preprocessBody:    "code exec response",
			expectedError:     false,
			expectedResponse:  "code exec response",
			expectedPayload:   "<?php echo 'test'; ?>",
			expectedHasMarked: true,
		},
		{
			description:     "error: not processed",
			filter:          false,
			preprocessError: preprocess.ErrNotProcessed,
			expectedError:   true,
		},
		{
			description:     "error: generic error",
			filter:          false,
			preprocessError: errors.New("processing failed"),
			expectedError:   true,
		},
		{
			description: "error: no payload found",
			filter:      false,
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  false,
				PayloadType: "",
				Payload:     "",
			},
			expectedError: true,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fdbc := &database.FakeDatabaseClient{}
			fakeJrunner := javascript.FakeJavascriptRunner{}
			alertManager := alerting.NewAlertManager(42)
			whoisManager := whois.FakeRdapManager{}
			queryRunner := FakeQueryRunner{ErrorToReturn: nil}
			reg := prometheus.NewRegistry()
			bMetrics := CreateBackendMetrics(reg)
			fakeLimiter := ratelimit.FakeRateLimiter{
				BoolToReturn:  true,
				ErrorToReturn: nil,
			}
			sMetrics := session.CreateSessionMetrics(reg)
			fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
			fIpMgr := analysis.FakeIpEventManager{}
			fakeRes := &responder.FakeResponder{}
			fakeDescriber := describer.FakeDescriberClient{ErrorToReturn: nil}

			fakePreprocessor := preprocess.FakePreProcessor{
				ResultToReturn: func() *preprocess.PreProcessResult {
					if test.preprocessResult != nil {
						return test.preprocessResult
					}
					return &preprocess.PreProcessResult{}
				}(),
				PayloadResult: &preprocess.PayloadProcessingResult{Output: test.preprocessBody},
				ErrorToReturn: test.preprocessError,
			}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

			// Setup test request
			req := &models.Request{
				CmpHash: "test_hash",
				Uri:     "/test",
			}

			// Populate cache if needed
			if test.cmpHashInCache {
				b.payloadCmpHashCache.Store("test_hash", struct{}{})
			}

			// Call the method
			response, err := b.GetPreProcessResponse(req, test.filter)

			// Verify error expectation
			if (err != nil) != test.expectedError {
				t.Errorf("expected error=%t, got error=%v", test.expectedError, err)
			}

			// If we don't expect an error, verify the response
			if !test.expectedError {
				if response.Output != test.expectedResponse {
					t.Errorf("expected response=%s, got=%+v", test.expectedResponse, response)
				}
				if req.TriagePayload != test.expectedPayload {
					t.Errorf("expected payload=%s, got=%s", test.expectedPayload, req.TriagePayload)
				}
				if req.TriageHasPayload != test.expectedHasMarked {
					t.Errorf("expected TriageHasPayload=%t, got=%t", test.expectedHasMarked, req.TriageHasPayload)
				}
			}
		})
	}
}

func TestHandlePreProcess(t *testing.T) {
	fdbc := &database.FakeDatabaseClient{}
	fakeJrunner := javascript.FakeJavascriptRunner{}
	alertManager := alerting.NewAlertManager(42)
	whoisManager := whois.FakeRdapManager{}
	queryRunner := FakeQueryRunner{}
	reg := prometheus.NewRegistry()
	bMetrics := CreateBackendMetrics(reg)
	fakeLimiter := ratelimit.FakeRateLimiter{
		BoolToReturn:  true,
		ErrorToReturn: nil,
	}
	sMetrics := session.CreateSessionMetrics(reg)
	fSessionMgr := session.NewDatabaseSessionManager(fdbc, time.Hour, sMetrics)
	fIpMgr := analysis.FakeIpEventManager{}
	fakeRes := &responder.FakeResponder{}
	fakeDescriber := describer.FakeDescriberClient{}

	for _, test := range []struct {
		description      string
		preprocessResult *preprocess.PreProcessResult
		payloadResponse  *preprocess.PayloadProcessingResult
		preprocessError  error
		expectedBody     string
		expectedHeaders  []string // Keys that should exist in headers
		expectedSqlDelay int
	}{
		{
			description: "Success with payload response",
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "SQLI",
				Payload:     "' OR 1=1 --",
			},
			payloadResponse: &preprocess.PayloadProcessingResult{
				Output:     "Injected content",
				Headers:    "X-Injected: true",
				SqlDelayMs: 0,
			},
			preprocessError: nil,
			expectedBody:    "Original content\nInjected content",
			expectedHeaders: []string{"X-Injected"},
		},
		{
			description:      "Error during preprocessing (ErrNotProcessed)",
			preprocessResult: nil,
			preprocessError:  preprocess.ErrNotProcessed,
			expectedBody:     "Original content",
		},
		{
			description: "Success with SQL delay",
			preprocessResult: &preprocess.PreProcessResult{
				HasPayload:  true,
				PayloadType: "SQLI",
			},
			payloadResponse: &preprocess.PayloadProcessingResult{
				Output:     "Delayed content",
				SqlDelayMs: 50, // Small delay for test
			},
			preprocessError: nil,
			expectedBody:    "Original content\nDelayed content",
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fakePreprocessor := preprocess.FakePreProcessor{
				ResultToReturn: test.preprocessResult,
				PayloadResult:  test.payloadResponse,
				ErrorToReturn:  test.preprocessError,
			}

			b := NewBackendServer(fdbc, bMetrics, &fakeJrunner, alertManager, &vt.FakeVTManager{}, &whoisManager, &queryRunner, &fakeLimiter, &fIpMgr, fakeRes, fSessionMgr, &fakeDescriber, &fakePreprocessor, GetDefaultBackendConfig())

			content := &models.Content{
				Data: []byte("Original content"),
			}
			res := &backend_service.HttpResponse{
				Body:   []byte("Original content"),
				Header: []*backend_service.KeyValue{},
			}
			finalHeaders := make(map[string]string)
			sReq := &models.Request{
				Uri: "/test",
			}

			startTime := time.Now()
			b.handlePreProcess(sReq, content, res, &finalHeaders, startTime, false)

			// Verify body
			if string(res.Body) != test.expectedBody {
				t.Errorf("expected body %q, got %q", test.expectedBody, string(res.Body))
			}

			// Verify headers
			for _, h := range test.expectedHeaders {
				if _, ok := finalHeaders[h]; !ok {
					t.Errorf("expected header %s to be present", h)
				}
			}
		})
	}
}

func TestCheckForConsecutivePayloads(t *testing.T) {
	for _, test := range []struct {
		description        string
		requests           []*models.Request
		preResults         []*preprocess.PreProcessResult
		expectedEventCount int
	}{
		{
			description: "Different payloads in same parameter creates event",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "id", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 1,
		},
		{
			description: "Same payload in same parameter creates no event",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 0,
		},
		{
			description: "Different session IDs do not share cache state",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 200, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "id", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 0,
		},
		{
			description: "Different CmpHash does not trigger event",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 100, CmpHash: "hash2", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "id", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 0,
		},
		{
			description: "Different targeted parameters do not trigger event",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "file", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 0,
		},
		{
			description: "Multiple different payloads create multiple events",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 2, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
				{ID: 3, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "id", PayloadType: constants.TriagePayloadTypeShellCommand},
				{TargetedParameter: "cmd", Payload: "uname -a", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 2,
		},
		{
			description: "Single request creates no event",
			requests: []*models.Request{
				{ID: 1, SessionID: 100, CmpHash: "hash1", SourceIP: "1.2.3.4", HoneypotIP: "5.6.7.8"},
			},
			preResults: []*preprocess.PreProcessResult{
				{TargetedParameter: "cmd", Payload: "whoami", PayloadType: constants.TriagePayloadTypeShellCommand},
			},
			expectedEventCount: 0,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fIpMgr := analysis.FakeIpEventManager{}

			b := &BackendServer{
				payloadSessionCache: util.NewStringMapCache[map[string]int64]("test", time.Hour),
				ipEventManager:      &fIpMgr,
			}

			for i, req := range test.requests {
				b.CheckForConsecutivePayloads(req, test.preResults[i])
			}

			if len(fIpMgr.Events) != test.expectedEventCount {
				t.Errorf("expected %d events, got %d", test.expectedEventCount, len(fIpMgr.Events))
			}

			// If we expect an event, verify it has the correct type and subtype.
			if test.expectedEventCount > 0 {
				evt := fIpMgr.Events[0]
				if evt.Type != constants.IpEventSessionInfo {
					t.Errorf("expected event type %s, got %s", constants.IpEventSessionInfo, evt.Type)
				}
				if evt.Subtype != constants.IpEventSubTypeSuccessivePayload {
					t.Errorf("expected event subtype %s, got %s", constants.IpEventSubTypeSuccessivePayload, evt.Subtype)
				}
			}
		})
	}
}

func TestLoadRules(t *testing.T) {
	for _, test := range []struct {
		description       string
		rulesPerGroupJoin []models.RulePerGroupJoin
		dbError           error
		expectError       bool
		expectedGroups    map[int64][]int64 // groupID -> list of rule IDs
	}{
		{
			description:       "empty rules",
			rulesPerGroupJoin: []models.RulePerGroupJoin{},
			expectError:       false,
			expectedGroups:    map[int64][]int64{},
		},
		{
			description: "single rule in single group",
			rulesPerGroupJoin: []models.RulePerGroupJoin{
				{
					Rule:         models.ContentRule{ID: 100},
					RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 100, GroupID: 10},
				},
			},
			expectError:    false,
			expectedGroups: map[int64][]int64{10: {100}},
		},
		{
			description: "multiple rules in single group",
			rulesPerGroupJoin: []models.RulePerGroupJoin{
				{
					Rule:         models.ContentRule{ID: 100},
					RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 100, GroupID: 10},
				},
				{
					Rule:         models.ContentRule{ID: 101},
					RulePerGroup: models.RulePerGroup{ID: 2, RuleID: 101, GroupID: 10},
				},
			},
			expectError:    false,
			expectedGroups: map[int64][]int64{10: {100, 101}},
		},
		{
			description: "rules in multiple groups",
			rulesPerGroupJoin: []models.RulePerGroupJoin{
				{
					Rule:         models.ContentRule{ID: 100},
					RulePerGroup: models.RulePerGroup{ID: 1, RuleID: 100, GroupID: 10},
				},
				{
					Rule:         models.ContentRule{ID: 101},
					RulePerGroup: models.RulePerGroup{ID: 2, RuleID: 101, GroupID: 20},
				},
				{
					Rule:         models.ContentRule{ID: 102},
					RulePerGroup: models.RulePerGroup{ID: 3, RuleID: 102, GroupID: 10},
				},
			},
			expectError:    false,
			expectedGroups: map[int64][]int64{10: {100, 102}, 20: {101}},
		},
		{
			description:       "database error",
			rulesPerGroupJoin: nil,
			dbError:           errors.New("db error"),
			expectError:       true,
			expectedGroups:    nil,
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			fakeDB := &database.FakeDatabaseClient{
				RulesPerGroupJoinToReturn: test.rulesPerGroupJoin,
				ErrorToReturn:             test.dbError,
			}

			b := &BackendServer{
				dbClient:  fakeDB,
				safeRules: &SafeRules{},
			}

			err := b.LoadRules()
			if test.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify the rules are correctly grouped by GroupID.
			rules := b.safeRules.Get()
			assert.Equal(t, len(test.expectedGroups), len(rules))

			for groupID, expectedRuleIDs := range test.expectedGroups {
				groupRules := b.safeRules.GetGroup(groupID)
				assert.Equal(t, len(expectedRuleIDs), len(groupRules), "group %d rule count mismatch", groupID)

				actualRuleIDs := make([]int64, len(groupRules))
				for i, r := range groupRules {
					actualRuleIDs[i] = r.ID
				}
				assert.Equal(t, expectedRuleIDs, actualRuleIDs, "group %d rule IDs mismatch", groupID)
			}
		})
	}
}
