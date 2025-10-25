package describer

import (
	"errors"
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
		metadata       []models.RequestMetadata
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
			llmResponse:    `{"description":"Test request","vulnerability_type":"none","application":"web","malicious":"yes", "has_payload": "no"}`,
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
			llmResponse:    `{"description":"Test request","vulnerability_type":"something","application":"web","malicious":"yes", "has_payload": "no"}`,
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
			llmResponse:    "```json\n{\"description\":\"Malicious request\",\"vulnerability_type\":\"sql_injection\",\"application\":\"web\",\"malicious\":\"yes\", \"has_payload\": \"no\"}\n```",
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
		{
			name:      "database update fails - continues processing without error",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 50,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:      50,
					Uri:     "/fail-update",
					CmpHash: "hash_fail",
					Raw:     "GET /fail-update HTTP/1.1",
					RuleID:  0,
				},
			},
			llmResponse:    `{"description":"Test update failure","vulnerability_type":"test","application":"web","malicious":"yes","has_payload":"no"}`,
			updateErr:      errors.New("database update failed"),
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 0, // No event should be added when update fails
		},
		{
			name:      "with base64 metadata",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 44,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:      44,
					Uri:     "/test-base64",
					CmpHash: "hash3",
					Raw:     "GET /test-base64 HTTP/1.1",
					RuleID:  0,
				},
			},
			metadata: []models.RequestMetadata{
				{
					RequestID: 44,
					Type:      constants.ExtractorTypeBase64,
					Data:      "Decoded base64 content for testing",
				},
			},
			llmResponse:    `{"description":"Test with base64 data","vulnerability_type":"base64_injection","application":"web","malicious":"yes", "has_payload": "yes"}`,
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 1,
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
				MetadataToReturn:            tt.metadata,
				ErrorToReturn:               nil,
				UpdateErrorToReturn:         tt.updateErr,
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

func TestApplicationLengthValidation(t *testing.T) {
	tests := []struct {
		name              string
		applicationLength int
		expectedEmpty     bool
	}{
		{
			name:              "application exactly 128 chars",
			applicationLength: 128,
			expectedEmpty:     false,
		},
		{
			name:              "application over 128 chars",
			applicationLength: 129,
			expectedEmpty:     true,
		},
	}

	reg := prometheus.NewRegistry()
	llmMetrics := llm.CreateLLMMetrics(reg)
	describerMetrics := CreateDescriberMetrics(reg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applicationValue := util.GenerateRandomString(tt.applicationLength, "abcdefghijklmnopqrstuvwxyz")

			mockDB := &database.FakeDatabaseClient{
				RequestDescriptionsToReturn: []models.RequestDescription{
					{
						ExampleRequestID: 1,
						TriageStatus:     constants.TriageStatusTypePending,
					},
				},
				RequestsToReturn: []models.Request{
					{
						ID:      1,
						Uri:     "/test",
						CmpHash: "hash1",
						Raw:     "GET /test HTTP/1.1",
					},
				},
			}

			llmResponse := `{"description":"Test","vulnerability_type":"none","application":"` + applicationValue + `","malicious":"no","has_payload":"no"}`

			mockLLMClient := &llm.MockLLMClient{
				CompletionToReturn: llmResponse,
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

			_, err := manager.GenerateLLMDescriptions(1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check if the application was set correctly
			updatedDesc := mockDB.LastDataModelSeen.(*models.RequestDescription)
			if tt.expectedEmpty && updatedDesc.AIApplication != "" {
				t.Errorf("expected empty AIApplication but got: %s", updatedDesc.AIApplication)
			}
			if !tt.expectedEmpty && updatedDesc.AIApplication != applicationValue {
				t.Errorf("expected AIApplication to be %s but got: %s", applicationValue, updatedDesc.AIApplication)
			}
		})
	}
}

