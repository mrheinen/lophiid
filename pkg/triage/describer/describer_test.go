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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					Raw:     []byte("GET /test HTTP/1.1"),
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
					Raw:     []byte("GET /test HTTP/1.1"),
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
					Raw:     []byte("GET /test HTTP/1.1"),
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
					Raw:     []byte("GET /fail-update HTTP/1.1"),
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
					Raw:     []byte("GET /test-base64 HTTP/1.1"),
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
		{
			name:      "triage has payload creates payload event",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 45,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:               45,
					Uri:              "/cmd?exec=whoami",
					CmpHash:          "hash_payload",
					Raw:              []byte("GET /cmd?exec=whoami HTTP/1.1"),
					RuleID:           0,
					TriageHasPayload: true,
					TriagePayloadType: "SHELL_COMMAND",
					SourceIP:         "10.0.0.1",
					HoneypotIP:       "192.168.1.1",
				},
			},
			llmResponse:    `{"description":"Shell command execution","vulnerability_type":"rce","application":"web","malicious":"no","has_payload":"yes"}`,
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 1, // Only payload event, no malicious event since malicious=no
		},
		{
			name:      "triage has payload with malicious creates two events",
			workCount: 1,
			descriptions: []models.RequestDescription{
				{
					ExampleRequestID: 46,
					TriageStatus:     constants.TriageStatusTypePending,
				},
			},
			requests: []models.Request{
				{
					ID:               46,
					Uri:              "/cmd?exec=rm+-rf",
					CmpHash:          "hash_payload_malicious",
					Raw:              []byte("GET /cmd?exec=rm+-rf HTTP/1.1"),
					RuleID:           0,
					TriageHasPayload: true,
					TriagePayloadType: "SHELL_COMMAND",
					SourceIP:         "10.0.0.2",
					HoneypotIP:       "192.168.1.2",
				},
			},
			llmResponse:    `{"description":"Malicious shell command","vulnerability_type":"rce","application":"web","malicious":"yes","has_payload":"yes"}`,
			expectedCount:  1,
			expectError:    false,
			expectedEvents: 2, // Both malicious event and payload event
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

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedCount, count)
			assert.Len(t, mockEvents.Events, tt.expectedEvents)
		})
	}
}

// TestTriagePayloadEventFields verifies that when TriageHasPayload is true,
// an IpEvent is created with the correct fields.
func TestTriagePayloadEventFields(t *testing.T) {
	reg := prometheus.NewRegistry()
	llmMetrics := llm.CreateLLMMetrics(reg)
	describerMetrics := CreateDescriberMetrics(reg)

	mockDB := &database.FakeDatabaseClient{
		RequestDescriptionsToReturn: []models.RequestDescription{
			{
				ID:               100,
				ExampleRequestID: 200,
				TriageStatus:     constants.TriageStatusTypePending,
				CmpHash:          "test_hash",
			},
		},
		RequestsToReturn: []models.Request{
			{
				ID:                200,
				Uri:               "/exploit?cmd=cat+/etc/passwd",
				CmpHash:           "test_hash",
				Raw:               []byte("GET /exploit?cmd=cat+/etc/passwd HTTP/1.1"),
				TriageHasPayload:  true,
				TriagePayloadType: "SHELL_COMMAND",
				SourceIP:          "192.168.1.100",
				HoneypotIP:        "10.0.0.50",
			},
		},
	}

	mockLLMClient := &llm.MockLLMClient{
		CompletionToReturn: `{"description":"Command execution attempt","vulnerability_type":"rce","application":"linux","malicious":"no","has_payload":"yes"}`,
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
	require.NoError(t, err)
	require.Len(t, mockEvents.Events, 1)

	evt := mockEvents.Events[0]

	assert.Equal(t, "192.168.1.100", evt.IP)
	assert.Equal(t, "10.0.0.50", evt.HoneypotIP)
	assert.Equal(t, constants.IpEventSourceAI, evt.Source)
	assert.Equal(t, int64(200), evt.RequestID)
	assert.Equal(t, "100", evt.SourceRef)
	assert.Equal(t, constants.IpEventRefTypeRequestDescriptionId, evt.SourceRefType)
	assert.Equal(t, constants.IpEventPayload, evt.Type)
	assert.Equal(t, constants.IpEventSubTypeNone, evt.Subtype)
	assert.Equal(t, "SHELL_COMMAND", evt.Details)
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
						Raw:     []byte("GET /test HTTP/1.1"),
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
			require.NoError(t, err)

			// Check if the application was set correctly
			updatedDesc := mockDB.LastDataModelSeen.(*models.RequestDescription)
			if tt.expectedEmpty {
				assert.Empty(t, updatedDesc.AIApplication)
			} else {
				assert.Equal(t, applicationValue, updatedDesc.AIApplication)
			}
		})
	}
}
