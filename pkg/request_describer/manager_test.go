package describer

import (
	"errors"
	"fmt"
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func GetLMManager(completionToReturn string) *llm.LLMManager {
	lmClient := llm.MockLLMClient{
		CompletionToReturn: completionToReturn,
		ErrorToReturn:      nil,
	}

	reg := prometheus.NewRegistry()
	metrics := llm.CreateLLMMetrics(reg)
	cache := util.NewStringMapCache[string]("foo", time.Minute)
	return llm.NewLLMManager(&lmClient, cache, metrics, time.Minute, 5)
}

func GetMetrics() *DescriberMetrics {
	reg := prometheus.NewRegistry()
	return CreateDescriberMetrics(reg)
}

func TestMaybeAddNewHash(t *testing.T) {

	t.Run("cache miss and db error", func(t *testing.T) {
		fakeDbClient := &database.FakeDatabaseClient{
			ErrorToReturn: errors.New("nope"),
		}

		eventMgr := analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(""), &eventMgr, time.Minute, GetMetrics(), 3)
		fakeHash := "ABCDEFGHIJKLMNOP"

		err := hm.MaybeAddNewHash(fakeHash, &models.Request{})
		if err == nil {
			t.Fatalf("expected error, got none")
		}

		if !strings.Contains(err.Error(), "nope") {
			t.Fatalf("expected error with text 'nope', got %s", err)
		}
	})

	t.Run("cache miss but in db", func(t *testing.T) {

		fakeHash := "ABCDEFGHIJKLMNOP"
		fakeDbClient := &database.FakeDatabaseClient{
			RequestDescriptionsToReturn: []models.RequestDescription{
				models.RequestDescription{
					CmpHash: fakeHash,
				},
			},
		}

		eventMgr := analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(""), &eventMgr, time.Minute, GetMetrics(), 3)
		err := hm.MaybeAddNewHash(fakeHash, &models.Request{})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		_, err = hm.cache.Get(fakeHash)
		if err != nil {
			t.Fatalf("expected cache entry for %s, got none", fakeHash)
		}
	})

	t.Run("missing in db and cache", func(t *testing.T) {
		fakeHash := "ABCDEFGHIJKLMNOP"
		fakeDbClient := &database.FakeDatabaseClient{}

		eventMgr := analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(""), &eventMgr, time.Minute, GetMetrics(), 3)
		err := hm.MaybeAddNewHash(fakeHash, &models.Request{})
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if len(hm.llmQueueMap) != 1 {
			t.Fatalf("expected 1 item in LLM queue, got %d", len(hm.llmQueueMap))
		}
		_, err = hm.cache.Get(fakeHash)
		if err != nil {
			t.Fatalf("expected cache entry for %s, got none", fakeHash)
		}
	})
}

func TestGenerateLLMDescriptionsOk(t *testing.T) {
	fakeDbClient := &database.FakeDatabaseClient{}

	testDescription := "description"
	testVulnerabilityType := "type"
	testApplication := "application"
	testMalicious := "true"
	testCVE := "CVE-1234-1234"

	completionToReturn := fmt.Sprintf(`{"description": "%s", "malicious": "%s", "vulnerability_type": "%s", "application": "%s", "cve": "%s"}`, testDescription, testMalicious, testVulnerabilityType, testApplication, testCVE)

	eventMgr := analysis.FakeIpEventManager{}
	hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(completionToReturn), &eventMgr, time.Minute, GetMetrics(), 3)

	err := hm.GenerateLLMDescriptions([]*QueueEntry{
		&QueueEntry{
			RequestDescription: &models.RequestDescription{},
			Request: &models.Request{
				Raw: "HTTP/1.0",
			},
		},
	})

	if err != nil {
		t.Errorf("failed to generate LLM descriptions: %s", err)
	}
}

func TestGenerateLLMDescriptionsErrorsOk(t *testing.T) {
	testDescription := "description"
	testVulnerabilityType := "type"
	testApplication := "application"
	testMalicious := "true"
	testCVE := "CVE-1234-1234"

	goodCompletionToReturn := fmt.Sprintf(`{"description": "%s", "malicious": "%s", "vulnerability_type": "%s", "application": "%s", "cve": "%s"}`, testDescription, testMalicious, testVulnerabilityType, testApplication, testCVE)

	for _, test := range []struct {
		description        string
		errorContains      string
		dbErrorToReturn    error
		completionToReturn string
	}{
		{
			description:        "fails on db error ok",
			errorContains:      "failed to insert",
			dbErrorToReturn:    errors.New("foo"),
			completionToReturn: goodCompletionToReturn,
		},
		{
			description:        "fails on json marshal error",
			errorContains:      "failed to parse LLM",
			dbErrorToReturn:    nil,
			completionToReturn: "AAA<><><",
		},
	} {

		t.Run(test.description, func(t *testing.T) {
			fakeDbClient := &database.FakeDatabaseClient{
				ErrorToReturn: test.dbErrorToReturn,
			}

			eventMgr := analysis.FakeIpEventManager{}
			hm := GetNewCachedDescriptionManager(
				fakeDbClient, GetLMManager(test.completionToReturn), &eventMgr, time.Minute, GetMetrics(), 3)
			err := hm.GenerateLLMDescriptions([]*QueueEntry{
				&QueueEntry{
					RequestDescription: &models.RequestDescription{},
					Request: &models.Request{
						Raw: "HTTP/1.0",
					},
				},
			})

			if err == nil {
				t.Fatalf("expected error, got none")
			}

			if !strings.Contains(err.Error(), test.errorContains) {
				t.Fatalf("expected error %s, got %s", test.errorContains, err)
			}
		})
	}
}

func TestGenerateLLMDescriptionsCreatesEvent(t *testing.T) {
	fakeDbClient := &database.FakeDatabaseClient{}

	testDescription := "description"
	testVulnerabilityType := "type"
	testApplication := "application"
	testCVE := "CVE-1234-1234"

	t.Run("creates event when malicious and no rule", func(t *testing.T) {
		completionToReturn := fmt.Sprintf(`{"description": "%s", "malicious": "yes", "vulnerability_type": "%s", "application": "%s", "cve": "%s"}`, 
			testDescription, testVulnerabilityType, testApplication, testCVE)

		eventMgr := &analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(completionToReturn), eventMgr, time.Minute, GetMetrics(), 3)

		testReq := &models.Request{
			ID:         123,
			RuleID:     0,
			SourceIP:   "1.2.3.4",
			HoneypotIP: "5.6.7.8",
			Raw:        "HTTP/1.0",
		}

		err := hm.GenerateLLMDescriptions([]*QueueEntry{
			{
				RequestDescription: &models.RequestDescription{},
				Request:           testReq,
			},
		})

		if err != nil {
			t.Fatalf("failed to generate LLM descriptions: %s", err)
		}

		if len(eventMgr.Events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(eventMgr.Events))
		}

		event := eventMgr.Events[0]
		if event.IP != testReq.SourceIP {
			t.Errorf("expected source IP %s, got %s", testReq.SourceIP, event.IP)
		}
		if event.HoneypotIP != testReq.HoneypotIP {
			t.Errorf("expected honeypot IP %s, got %s", testReq.HoneypotIP, event.HoneypotIP)
		}
		if event.SourceRef != "123" {
			t.Errorf("expected source ref '123', got %s", event.SourceRef)
		}
	})

	t.Run("no event when not malicious", func(t *testing.T) {
		completionToReturn := fmt.Sprintf(`{"description": "%s", "malicious": "no", "vulnerability_type": "%s", "application": "%s", "cve": "%s"}`, 
			testDescription, testVulnerabilityType, testApplication, testCVE)

		eventMgr := &analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(completionToReturn), eventMgr, time.Minute, GetMetrics(), 3)

		err := hm.GenerateLLMDescriptions([]*QueueEntry{
			{
				RequestDescription: &models.RequestDescription{},
				Request: &models.Request{
					RuleID: 0,
					Raw:    "HTTP/1.0",
				},
			},
		})

		if err != nil {
			t.Fatalf("failed to generate LLM descriptions: %s", err)
		}

		if len(eventMgr.Events) != 0 {
			t.Fatalf("expected no events, got %d", len(eventMgr.Events))
		}
	})

	t.Run("no event when has rule", func(t *testing.T) {
		completionToReturn := fmt.Sprintf(`{"description": "%s", "malicious": "yes", "vulnerability_type": "%s", "application": "%s", "cve": "%s"}`, 
			testDescription, testVulnerabilityType, testApplication, testCVE)

		eventMgr := &analysis.FakeIpEventManager{}
		hm := GetNewCachedDescriptionManager(fakeDbClient, GetLMManager(completionToReturn), eventMgr, time.Minute, GetMetrics(), 3)

		err := hm.GenerateLLMDescriptions([]*QueueEntry{
			{
				RequestDescription: &models.RequestDescription{},
				Request: &models.Request{
					RuleID: 1,
					Raw:    "HTTP/1.0",
				},
			},
		})

		if err != nil {
			t.Fatalf("failed to generate LLM descriptions: %s", err)
		}

		if len(eventMgr.Events) != 0 {
			t.Fatalf("expected no events, got %d", len(eventMgr.Events))
		}
	})
}
