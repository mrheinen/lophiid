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
package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/rulegeneration/tools"
	"lophiid/pkg/util/constants"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSearch is a minimal SearchProvider for tests.
type fakeSearch struct {
	results []tools.SearchResult
	err     error
}

func (f *fakeSearch) Search(_ context.Context, _ string, _ int) ([]tools.SearchResult, error) {
	return f.results, f.err
}

func newWebTools(search tools.SearchProvider) *tools.WebTools {
	return tools.NewWebTools(search)
}

func newDBTools(db database.DatabaseClient) *tools.DatabaseTools {
	return tools.NewDatabaseTools(db, false)
}

func newEvalTools(db database.DatabaseClient, window time.Duration) *tools.EvalTools {
	return tools.NewEvalTools(db, window, 100, 0.10, 5, 20)
}

// --- web_search ---

func TestWebSearch_ReturnsResults(t *testing.T) {
	search := &fakeSearch{results: []tools.SearchResult{
		{Title: "ExploitDB", URL: "https://exploit-db.com/exploits/1", Snippet: "some exploit"},
	}}
	wt := newWebTools(search)

	args, _ := json.Marshal(map[string]string{"query": "CVE-2024-1234 exploitdb"})
	result, err := wt.WebSearchTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "ExploitDB")
	assert.Contains(t, result, "https://exploit-db.com/exploits/1")
}

func TestWebSearch_NoResults(t *testing.T) {
	search := &fakeSearch{results: nil}
	wt := newWebTools(search)

	args, _ := json.Marshal(map[string]string{"query": "something obscure"})
	result, err := wt.WebSearchTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "No results found")
}

func TestWebSearch_SearchError(t *testing.T) {
	search := &fakeSearch{err: fmt.Errorf("network error")}
	wt := newWebTools(search)

	args, _ := json.Marshal(map[string]string{"query": "test"})
	_, err := wt.WebSearchTool(context.Background(), string(args))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "network error")
}

// --- fetch_url ---

func TestFetchURL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	wt := newWebTools(&fakeSearch{})
	args, _ := json.Marshal(map[string]string{"url": srv.URL})
	result, err := wt.FetchURLTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "hello world")
}

func TestFetchURL_BadArgs(t *testing.T) {
	wt := newWebTools(&fakeSearch{})
	_, err := wt.FetchURLTool(context.Background(), "not json")
	assert.Error(t, err)
}

// --- list_existing_rules ---

func TestListExistingRules_ReturnsMatchingRules(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{
			{ID: 1, Uri: "/admin", Enabled: true, IsDraft: false, Method: "GET", UriMatching: "exact"},
			{ID: 2, Uri: "/admin/login", Enabled: true, IsDraft: false, Method: "POST", UriMatching: "prefix"},
		},
	}
	dt := newDBTools(fakeDB)

	args, _ := json.Marshal(map[string]string{"uri_pattern": "/admin"})
	result, err := dt.ListExistingRulesTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "ID=1")
	assert.Contains(t, result, "ID=2")
	assert.Contains(t, result, "/admin/login")
}

func TestListExistingRules_NoMatches(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{},
	}
	dt := newDBTools(fakeDB)

	args, _ := json.Marshal(map[string]string{"uri_pattern": "/nonexistent"})
	result, err := dt.ListExistingRulesTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "No existing rules")
}

// --- list_apps ---

func TestListApps_ReturnsList(t *testing.T) {
	ver := "1.0"
	vendor := "Apache"
	fakeDB := &database.FakeDatabaseClient{
		ApplicationToReturn: models.Application{ID: 10, Name: "Apache HTTP Server", Version: &ver, Vendor: &vendor},
	}
	dt := newDBTools(fakeDB)

	result, err := dt.ListAppsTool(context.Background(), "{}")

	require.NoError(t, err)
	assert.Contains(t, result, "ID=10")
	assert.Contains(t, result, "Apache HTTP Server")
}

func TestListApps_HasOutput(t *testing.T) {
	ver := "2.0"
	vendor := "NGINX"
	fakeDB := &database.FakeDatabaseClient{
		ApplicationToReturn: models.Application{ID: 5, Name: "nginx", Version: &ver, Vendor: &vendor},
	}
	dt := newDBTools(fakeDB)

	result, err := dt.ListAppsTool(context.Background(), "{}")

	require.NoError(t, err)
	assert.Contains(t, result, "ID=5")
	assert.Contains(t, result, "nginx")
}

// --- create_draft ---

func TestCreateDraft_NewApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	dt := newDBTools(fakeDB)

	input := tools.CreateDraftInput{
		App: &tools.DraftApp{
			Name:    "Struts",
			Version: "2.5.10",
			Vendor:  "Apache",
			CVES:    []string{"CVE-2017-5638"},
		},
		Content: tools.DraftContent{
			Name:        "Struts RCE 200",
			Description: "Synthesised from S2-045 PoC response",
			Data:        "<html>ok</html>",
			StatusCode:  "200",
			ContentType: "text/html",
		},
		Rule: tools.DraftRule{
			URI:            "/struts2-showcase",
			URIMatching:    "prefix",
			Method:         "POST",
			RequestPurpose: "EXPLOITATION",
		},
	}
	args, _ := json.Marshal(input)
	result, err := dt.CreateDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "draft created")
}

func TestCreateDraft_ExistingApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	dt := newDBTools(fakeDB)

	input := tools.CreateDraftInput{
		Content: tools.DraftContent{
			Name:        "Test content",
			Description: "Test",
			Data:        "hello",
			StatusCode:  "200",
		},
		Rule: tools.DraftRule{
			URI:            "/test",
			URIMatching:    "exact",
			Method:         "GET",
			RequestPurpose: "RECON",
			AppID:          99,
		},
	}
	args, _ := json.Marshal(input)
	result, err := dt.CreateDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "app_id=99")
}

func TestCreateDraft_DryRun(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	dt := tools.NewDatabaseTools(fakeDB, true)

	input := tools.CreateDraftInput{
		Content: tools.DraftContent{
			Name: "x", Description: "y", Data: "z", StatusCode: "200",
		},
		Rule: tools.DraftRule{
			URI: "/foo", URIMatching: "exact", Method: "GET",
			RequestPurpose: "UNKNOWN", AppID: 1,
		},
	}
	args, _ := json.Marshal(input)
	result, err := dt.CreateDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "dry-run")
}

func TestCreateDraft_MissingApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	dt := newDBTools(fakeDB)

	input := tools.CreateDraftInput{
		Content: tools.DraftContent{
			Name: "x", Description: "y", Data: "z", StatusCode: "200",
		},
		Rule: tools.DraftRule{
			URI: "/foo", URIMatching: "exact", Method: "GET",
			RequestPurpose: "UNKNOWN",
		},
	}
	args, _ := json.Marshal(input)
	_, err := dt.CreateDraftTool(context.Background(), string(args))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "app_id")
}

// --- get_candidate_rules_for_evaluation ---

func TestGetCandidateRules_ReturnsCandidates(t *testing.T) {
	src := constants.SourceTypeRuleAgent
	approved := time.Now().Add(-48 * time.Hour)
	oldEval := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{
			{ID: 10, Source: &src, ApprovedAt: &approved, LastEvaluatedAt: oldEval},
			{ID: 11, Source: &src, ApprovedAt: &approved, LastEvaluatedAt: oldEval},
		},
	}
	et := newEvalTools(fakeDB, 24*time.Hour)

	result, err := et.GetCandidateRulesForEvaluationTool(context.Background(), "{}")

	require.NoError(t, err)
	assert.Contains(t, result, "rule_id=10")
	assert.Contains(t, result, "rule_id=11")
}

func TestGetCandidateRules_NoCandidates(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{},
	}
	et := newEvalTools(fakeDB, 24*time.Hour)

	result, err := et.GetCandidateRulesForEvaluationTool(context.Background(), "{}")

	require.NoError(t, err)
	assert.Contains(t, result, "No candidate rules found")
}

func TestGetCandidateRules_DBError(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ErrorToReturn: fmt.Errorf("db connection lost"),
	}
	et := newEvalTools(fakeDB, 24*time.Hour)

	_, err := et.GetCandidateRulesForEvaluationTool(context.Background(), "{}")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db connection lost")
}

// --- evaluate_rule_performance ---

// makeEvalDB builds a FakeDatabaseClient preconfigured for evaluation tests.
func makeEvalDB(approvedAt time.Time, afterReqs []models.Request, paramQueue []any) *database.FakeDatabaseClient {
	src := constants.SourceTypeRuleAgent
	return &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{
			{ID: 1, Source: &src, ApprovedAt: &approvedAt, LastEvaluatedAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
		RequestsToReturn:               afterReqs,
		ParameterizedQueryResultsQueue: paramQueue,
	}
}

func TestEvaluateRule_ProgressedByDepth(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{
		{ID: 1, BaseHash: "abc", SessionID: 10},
	}
	beforeKCs := []models.KillChain{{ID: 1, MaxPhaseDepth: 1, PhaseCount: 1}}
	afterKCs := []models.KillChain{{ID: 2, MaxPhaseDepth: 3, PhaseCount: 1}, {ID: 3, MaxPhaseDepth: 3, PhaseCount: 1}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		beforeKCs,
		afterKCs,
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	var reply tools.JSONStatusReply
	require.NoError(t, json.Unmarshal([]byte(result), &reply))
	assert.Equal(t, tools.JSONStatusSuccess, reply.Status)
	assert.Contains(t, reply.StatusMessage, "effective")
}

func TestEvaluateRule_ProgressedByPhaseCount(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{
		{ID: 1, BaseHash: "abc", SessionID: 10},
	}
	beforeKCs := []models.KillChain{{ID: 1, MaxPhaseDepth: 2, PhaseCount: 1}}
	afterKCs := []models.KillChain{{ID: 2, MaxPhaseDepth: 2, PhaseCount: 3}, {ID: 3, MaxPhaseDepth: 2, PhaseCount: 3}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		beforeKCs,
		afterKCs,
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	var reply tools.JSONStatusReply
	require.NoError(t, json.Unmarshal([]byte(result), &reply))
	assert.Equal(t, tools.JSONStatusSuccess, reply.Status)
	assert.Contains(t, reply.StatusMessage, "effective")
}

func TestEvaluateRule_NotProgressed(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{
		{ID: 1, BaseHash: "abc", SessionID: 10},
	}
	kcs := []models.KillChain{{ID: 1, MaxPhaseDepth: 2, PhaseCount: 2}, {ID: 2, MaxPhaseDepth: 2, PhaseCount: 2}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		kcs,
		kcs,
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	var reply tools.JSONStatusReply
	require.NoError(t, json.Unmarshal([]byte(result), &reply))
	assert.Equal(t, tools.JSONStatusSuccess, reply.Status)
	assert.Contains(t, reply.StatusMessage, "content")
}

func TestEvaluateRule_NoData_NoAfterRequests(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	fakeDB := makeEvalDB(approved, []models.Request{}, nil)
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "No data")
}

func TestEvaluateRule_RuleNotMatching(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	reqID := int64(42)
	fakeDB := makeEvalDB(approved, []models.Request{}, []any{
		[]models.RuleManagementLog{{RequestID: &reqID}},
		[]tools.RequestCountRow{{Count: 3}},
	})
	fakeDB.RequestToReturn = models.Request{BaseHash: "abc123"}
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	var reply tools.JSONStatusReply
	require.NoError(t, json.Unmarshal([]byte(result), &reply))
	assert.Equal(t, tools.JSONStatusSuccess, reply.Status)
	assert.Contains(t, reply.StatusMessage, "not matching")
}

func TestEvaluateRule_NoData_NoBeforeKillChains(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{{ID: 1, BaseHash: "abc", SessionID: 10}}
	afterKCs := []models.KillChain{{ID: 2, MaxPhaseDepth: 3, PhaseCount: 2}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		[]models.KillChain{},
		afterKCs,
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "Insufficient kill chain")
}

func TestEvaluateRule_NoData_NoAfterKillChains(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{{ID: 1, BaseHash: "abc", SessionID: 10}}
	beforeKCs := []models.KillChain{{ID: 1, MaxPhaseDepth: 1, PhaseCount: 1}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		beforeKCs,
		[]models.KillChain{},
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "Insufficient kill chain")
}

func TestEvaluateRule_RuleNotFound(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{},
	}
	et := newEvalTools(fakeDB, 24*time.Hour)

	args, _ := json.Marshal(map[string]int64{"rule_id": 999})
	_, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestEvaluateRule_MissingApprovedAt(t *testing.T) {
	src := constants.SourceTypeRuleAgent
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{
			{ID: 1, Source: &src, ApprovedAt: nil},
		},
	}
	et := newEvalTools(fakeDB, 24*time.Hour)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	result, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, tools.JSONStatusError)
}

func TestEvaluateRule_UpdatesLastEvaluatedAt(t *testing.T) {
	approved := time.Now().Add(-48 * time.Hour)
	afterReqs := []models.Request{{ID: 1, BaseHash: "abc", SessionID: 10}}
	kcs := []models.KillChain{{ID: 1, MaxPhaseDepth: 2, PhaseCount: 2}, {ID: 2, MaxPhaseDepth: 2, PhaseCount: 2}}

	fakeDB := makeEvalDB(approved, afterReqs, []any{
		[]models.Request{{ID: 2, BaseHash: "abc", SessionID: 20}},
		kcs,
		kcs,
	})
	et := tools.NewEvalTools(fakeDB, 24*time.Hour, 100, 0.10, 5, 20)

	args, _ := json.Marshal(map[string]int64{"rule_id": 1})
	_, err := et.EvaluateRulePerformanceTool(context.Background(), string(args))

	require.NoError(t, err)
	require.NotNil(t, fakeDB.LastDataModelSeen)
	updatedRule, ok := fakeDB.LastDataModelSeen.(*models.ContentRule)
	require.True(t, ok, "LastDataModelSeen should be *models.ContentRule")
	assert.True(t, updatedRule.LastEvaluatedAt.After(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)),
		"LastEvaluatedAt should have been updated beyond 2000-01-01")
}

func TestEvaluateRule_BadArgs(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	et := newEvalTools(fakeDB, 24*time.Hour)

	_, err := et.EvaluateRulePerformanceTool(context.Background(), "not json")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parsing evaluate_rule_performance args")
}
