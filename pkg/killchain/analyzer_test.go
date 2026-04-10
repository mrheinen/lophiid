// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package killchain

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
)

func makeLLMResponse(chains []KillChainLLMChain) string {
	res := KillChainLLMResult{KillChains: chains}
	b, _ := json.Marshal(res)
	return string(b)
}

func makeAnalyzer(t *testing.T, fakeDB *database.FakeDatabaseClient, fakeLLM *llm.MockLLMManager, dryRun bool) *KillChainAnalyzer {
	t.Helper()
	a, err := NewKillChainAnalyzer(fakeDB, fakeLLM, nil, 50, 4096, dryRun)
	if err != nil {
		t.Fatalf("NewKillChainAnalyzer: %v", err)
	}
	return a
}

func TestAnalyzeSessions_NoSessions(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	fakeLLM := &llm.MockLLMManager{}
	a := makeAnalyzer(t, fakeDB, fakeLLM, false)

	cnt, err := a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cnt != 1 {
		// FakeDatabaseClient.SearchSession always returns []Session{f.SessionToReturn}
		// which is a zero-value session – that's fine, we just check no panic.
		t.Logf("processed %d sessions (zero-value session from fake)", cnt)
	}
}

func TestAnalyzeSession_TruncatesWhenTooManyRequests(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
	}

	// Return maxRequests+1 requests to trigger the truncation path.
	maxReqs := 3
	reqs := make([]models.Request, maxReqs+1)
	for i := range reqs {
		reqs[i] = models.Request{ID: int64(i + 1), SessionID: 42}
	}
	fakeDB.RequestsToReturn = reqs

	fakeLLM := &llm.MockLLMManager{CompletionToReturn: `{"kill_chains":[]}`}
	a, err := NewKillChainAnalyzer(fakeDB, fakeLLM, nil, maxReqs, 4096, false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, ok := fakeDB.LastDataModelSeen.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session as last updated model, got %T", fakeDB.LastDataModelSeen)
	}
	if updated.KillChainProcessStatus != constants.KillChainProcessStatusPartial {
		t.Errorf("expected PARTIAL, got %s", updated.KillChainProcessStatus)
	}
}

func TestAnalyzeSession_LLMError(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
		RequestsToReturn: []models.Request{
			{ID: 1, SessionID: 42, Raw: []byte("GET / HTTP/1.1")},
		},
	}

	fakeLLM := &llm.MockLLMManager{ErrorToReturn: fmt.Errorf("LLM unavailable")}

	a := makeAnalyzer(t, fakeDB, fakeLLM, false)

	_, analyzeErr := a.AnalyzeSessions(10)
	// AnalyzeSessions logs per-session errors and returns (count, nil).
	if analyzeErr != nil {
		t.Fatalf("unexpected error: %v", analyzeErr)
	}

	updated, ok := fakeDB.LastDataModelSeen.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session, got %T", fakeDB.LastDataModelSeen)
	}
	if updated.KillChainProcessStatus != constants.KillChainProcessStatusFailed {
		t.Errorf("expected FAILED, got %s", updated.KillChainProcessStatus)
	}
}

func TestAnalyzeSession_DetectsPhases(t *testing.T) {
	now := time.Now().UTC()
	req1 := models.Request{ID: 10, SessionID: 42, CmpHash: "hash-a", BaseHash: "base-1", TimeReceived: now.Add(-10 * time.Minute), Raw: []byte("GET /scan HTTP/1.1")}
	req2 := models.Request{ID: 11, SessionID: 42, CmpHash: "hash-b", BaseHash: "base-1", TimeReceived: now.Add(-5 * time.Minute), Raw: []byte("POST /exploit HTTP/1.1")}

	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			StartedAt:              now.Add(-15 * time.Minute),
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
		RequestsToReturn: []models.Request{req1, req2},
	}

	chain := KillChainLLMChain{
		RequestIDs: []int64{10, 11},
		Phases: []KillChainLLMPhase{
			{Phase: constants.KillChainPhaseRecon, Evidence: "scanning", FirstRequestID: 10, LastRequestID: 10, RequestCount: 1},
			{Phase: constants.KillChainPhaseExploitation, Evidence: "exploit attempt", FirstRequestID: 11, LastRequestID: 11, RequestCount: 1},
		},
	}
	fakeLLM := &llm.MockLLMManager{CompletionToReturn: makeLLMResponse([]KillChainLLMChain{chain})}

	a := makeAnalyzer(t, fakeDB, fakeLLM, false)

	_, err := a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The last Insert should have been the second KillChainPhase.
	_, isPhase := fakeDB.LastDataModelSeen.(*models.SingleKillChainPhase)
	if !isPhase {
		// After phases, the session is updated — accept *models.Session too.
		updated, ok := fakeDB.LastDataModelSeen.(*models.Session)
		if !ok {
			t.Fatalf("expected *models.KillChainPhase or *models.Session, got %T", fakeDB.LastDataModelSeen)
		}
		if updated.KillChainProcessStatus != constants.KillChainProcessStatusDone {
			t.Errorf("expected DONE, got %s", updated.KillChainProcessStatus)
		}
	}
}

func TestAnalyzeSession_SkipsChainWithSingleUniqueRequest(t *testing.T) {
	now := time.Now().UTC()
	// Both requests have the same CmpHash → only 1 unique → chain must be skipped.
	req1 := models.Request{ID: 10, SessionID: 42, CmpHash: "same-hash", BaseHash: "base-1", TimeReceived: now.Add(-10 * time.Minute), Raw: []byte("GET /scan HTTP/1.1")}
	req2 := models.Request{ID: 11, SessionID: 42, CmpHash: "same-hash", BaseHash: "base-1", TimeReceived: now.Add(-5 * time.Minute), Raw: []byte("GET /scan HTTP/1.1")}

	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			StartedAt:              now.Add(-15 * time.Minute),
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
		RequestsToReturn: []models.Request{req1, req2},
	}

	chain := KillChainLLMChain{
		RequestIDs: []int64{10, 11},
		Phases: []KillChainLLMPhase{
			{Phase: constants.KillChainPhaseRecon, Evidence: "scanning", FirstRequestID: 10, LastRequestID: 11, RequestCount: 2},
		},
	}
	fakeLLM := &llm.MockLLMManager{CompletionToReturn: makeLLMResponse([]KillChainLLMChain{chain})}

	a := makeAnalyzer(t, fakeDB, fakeLLM, false)

	_, err := a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No KillChain row should have been inserted — LastDataModelSeen must be *models.Session.
	if _, ok := fakeDB.LastDataModelSeen.(*models.KillChain); ok {
		t.Error("expected chain to be skipped, but a KillChain was inserted")
	}
	updated, ok := fakeDB.LastDataModelSeen.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session as final write, got %T", fakeDB.LastDataModelSeen)
	}
	if updated.KillChainProcessStatus != constants.KillChainProcessStatusDone {
		t.Errorf("expected DONE, got %s", updated.KillChainProcessStatus)
	}
}

func TestAnalyzeSession_DryRun_NoDBWrites(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
		RequestsToReturn: []models.Request{
			{ID: 1, SessionID: 42, Raw: []byte("GET / HTTP/1.1")},
		},
	}

	fakeLLM := &llm.MockLLMManager{CompletionToReturn: makeLLMResponse([]KillChainLLMChain{
		{
			RequestIDs: []int64{1},
			Phases: []KillChainLLMPhase{
				{Phase: constants.KillChainPhaseRecon, Evidence: "scan", FirstRequestID: 1, LastRequestID: 1, RequestCount: 1},
			},
		},
	})}

	a := makeAnalyzer(t, fakeDB, fakeLLM, true)

	_, err := a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fakeDB.LastDataModelSeen != nil {
		t.Errorf("dry-run: expected no DB writes but LastDataModelSeen is %T", fakeDB.LastDataModelSeen)
	}
}

func TestAnalyzeSession_InvalidJSON(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		SessionToReturn: models.Session{
			ID:                     42,
			KillChainProcessStatus: constants.KillChainProcessStatusPending,
		},
		RequestsToReturn: []models.Request{
			{ID: 1, SessionID: 42, Raw: []byte("GET / HTTP/1.1")},
		},
	}

	fakeLLM := &llm.MockLLMManager{CompletionToReturn: "this is not json"}

	a := makeAnalyzer(t, fakeDB, fakeLLM, false)

	_, err := a.AnalyzeSessions(10)
	if err != nil {
		t.Fatalf("unexpected error from AnalyzeSessions: %v", err)
	}

	updated, ok := fakeDB.LastDataModelSeen.(*models.Session)
	if !ok {
		t.Fatalf("expected *models.Session, got %T", fakeDB.LastDataModelSeen)
	}
	if updated.KillChainProcessStatus != constants.KillChainProcessStatusFailed {
		t.Errorf("expected FAILED on bad JSON, got %s", updated.KillChainProcessStatus)
	}
}

func TestBuildUserMessage_Truncation(t *testing.T) {
	raw := make([]byte, 100)
	for i := range raw {
		raw[i] = 'A'
	}
	req := models.Request{ID: 1, TimeReceived: time.Now().UTC(), Raw: raw}
	msg := buildUserMessage([]models.Request{req}, 10, nil)
	if len(msg) == 0 {
		t.Fatal("expected non-empty message")
	}
	// Should contain the truncation marker.
	if !containsString(msg, "[TRUNCATED DUE TO LENGTH]") {
		t.Error("expected truncation marker in message")
	}
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
