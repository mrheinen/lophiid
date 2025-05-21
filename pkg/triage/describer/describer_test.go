package describer

import (
	"lophiid/pkg/analysis"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestGenerateLLMDescriptions(t *testing.T) {
	tests := []struct {
		name           string
		workCount      int64
		descriptions   []models.RequestDescription
		requests       []models.Request
		llmResponse    string
		llmError       error
		updateErr      error
		expectedCount  int64
		expectError    bool
		expectedEvents int
	}{
		{
			name:      "successful processing, no event",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 1,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:      1,
					Uri:     "/test",
					CmpHash: "hash1",
					Raw:     "GET /test HTTP/1.1",
					RuleID:  4,
				},
			},
			llmResponse:    `{"description":"Test request","vulnerability_type":"none","application":"web","malicious":"yes"}`,
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 1,
		},
		{
			name:      "successful processing sends event",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 42,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:      42,
					Uri:     "/test",
					CmpHash: "hash1",
					Raw:     "GET /test HTTP/1.1",
					RuleID:  0,
				},
			},
			llmResponse:    `{"description":"Test request","vulnerability_type":"something","application":"web","malicious":"yes"}`,
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 1,
		},
		{
			name:      "trims json code block markers with malicious content",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 43,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:      43,
					Uri:     "/test",
					CmpHash: "hash2",
					Raw:     "GET /test HTTP/1.1",
					RuleID:  0,
				},
			},
			llmResponse:    "```json\n{\"description\":\"Malicious request\",\"vulnerability_type\":\"sql_injection\",\"application\":\"web\",\"malicious\":\"yes\"}\n```",
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 1,
		},
		{
			name:           "no pending descriptions",
			workCount:      1,
			descriptions:   []models.RequestDescription{},
			expectedCount:  0,
			expectError:    false,
			expectedEvents: 0,
		},
	}

	reg := prometheus.NewRegistry()
	llmMetrics := llm.CreateLLMMetrics(reg)
	describerMetrics := CreateDescriberMetrics(reg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := &database.FakeDatabaseClient{
				RequestDescriptionsToReturn: tt.descriptions,
				RequestsToReturn:            tt.requests,
				ErrorToReturn:               tt.updateErr,
			}

			mockLLMClient := &llm.MockLLMClient{
				CompletionToReturn: tt.llmResponse,
				ErrorToReturn:      tt.llmError,
			}

			mockEvents := &analysis.FakeIpEventManager{}

			llmManager := llm.NewLLMManager(
				mockLLMClient,
				util.NewStringMapCache[string]("test-cache", time.Minute),
				llmMetrics,
				time.Second*10,
				5,
				true,
				"",
				"",
			)

			manager := &CachedDescriptionManager{
				dbClient:     mockDB,
				llmManager:   llmManager,
				eventManager: mockEvents,
				metrics:      describerMetrics,
			}

			count, err := manager.GenerateLLMDescriptions(tt.workCount)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if count != tt.expectedCount {
				t.Errorf("expected count %d but got %d", tt.expectedCount, count)
			}
			if len(mockEvents.Events) != tt.expectedEvents {
				t.Errorf("expected %d events but got %d", tt.expectedEvents, len(mockEvents.Events))
			}
		})
	}
}
