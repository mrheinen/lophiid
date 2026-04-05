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
package rulegeneration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"lophiid/pkg/database"
	"lophiid/pkg/database/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSearch is a minimal SearchProvider for tests.
type fakeSearch struct {
	results []SearchResult
	err     error
}

func (f *fakeSearch) Search(_ context.Context, _ string, _ int) ([]SearchResult, error) {
	return f.results, f.err
}

func newTestToolSet(t *testing.T, db database.DatabaseClient, search SearchProvider) *ToolSet {
	t.Helper()
	return NewToolSet(db, search, 42, false, "", 5)
}

// --- web_search ---

func TestWebSearch_ReturnsResults(t *testing.T) {
	search := &fakeSearch{results: []SearchResult{
		{Title: "ExploitDB", URL: "https://exploit-db.com/exploits/1", Snippet: "some exploit"},
	}}
	ts := newTestToolSet(t, nil, search)

	args, _ := json.Marshal(map[string]string{"query": "CVE-2024-1234 exploitdb"})
	result, err := ts.webSearchTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "ExploitDB")
	assert.Contains(t, result, "https://exploit-db.com/exploits/1")
}

func TestWebSearch_NoResults(t *testing.T) {
	search := &fakeSearch{results: nil}
	ts := newTestToolSet(t, nil, search)

	args, _ := json.Marshal(map[string]string{"query": "something obscure"})
	result, err := ts.webSearchTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Equal(t, "No results found.", result)
}

func TestWebSearch_SearchError(t *testing.T) {
	search := &fakeSearch{err: fmt.Errorf("network error")}
	ts := newTestToolSet(t, nil, search)

	args, _ := json.Marshal(map[string]string{"query": "test"})
	_, err := ts.webSearchTool(context.Background(), string(args))

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

	ts := newTestToolSet(t, nil, &fakeSearch{})
	args, _ := json.Marshal(map[string]string{"url": srv.URL})
	result, err := ts.fetchURLTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Equal(t, "hello world", result)
}

func TestFetchURL_BadArgs(t *testing.T) {
	ts := newTestToolSet(t, nil, &fakeSearch{})
	_, err := ts.fetchURLTool(context.Background(), "not json")
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
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	args, _ := json.Marshal(map[string]string{"uri_pattern": "/admin"})
	result, err := ts.listExistingRulesTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "ID=1")
	assert.Contains(t, result, "ID=2")
	assert.Contains(t, result, `URI="/admin/login"`)
}

func TestListExistingRules_NoMatches(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{
		ContentRulesToReturn: []models.ContentRule{},
	}
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	args, _ := json.Marshal(map[string]string{"uri_pattern": "/nonexistent"})
	result, err := ts.listExistingRulesTool(context.Background(), string(args))

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
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	result, err := ts.listAppsTool(context.Background(), "{}")

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
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	result, err := ts.listAppsTool(context.Background(), "{}")

	require.NoError(t, err)
	assert.Contains(t, result, "ID=5")
	assert.Contains(t, result, "nginx")
}

// --- create_draft ---

func TestCreateDraft_NewApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	input := CreateDraftInput{
		App: &DraftApp{
			Name:    "Struts",
			Version: "2.5.10",
			Vendor:  "Apache",
			CVES:    []string{"CVE-2017-5638"},
		},
		Content: DraftContent{
			Name:        "Struts RCE 200",
			Description: "Synthesised from S2-045 PoC response",
			Data:        "<html>ok</html>",
			StatusCode:  "200",
			ContentType: "text/html",
		},
		Rule: DraftRule{
			URI:            "/struts2-showcase",
			URIMatching:    "prefix",
			Method:         "POST",
			RequestPurpose: "ATTACK",
		},
	}
	args, _ := json.Marshal(input)
	result, err := ts.createDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "draft created")
}

func TestCreateDraft_ExistingApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	input := CreateDraftInput{
		Content: DraftContent{
			Name:        "Test content",
			Description: "Test",
			Data:        "hello",
			StatusCode:  "200",
		},
		Rule: DraftRule{
			URI:            "/test",
			URIMatching:    "exact",
			Method:         "GET",
			RequestPurpose: "RECON",
			AppID:          99,
		},
	}
	args, _ := json.Marshal(input)
	result, err := ts.createDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "app_id=99")
}

func TestCreateDraft_DryRun(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	ts := NewToolSet(fakeDB, &fakeSearch{}, 1, true, "", 5)

	input := CreateDraftInput{
		Content: DraftContent{
			Name: "x", Description: "y", Data: "z", StatusCode: "200",
		},
		Rule: DraftRule{
			URI: "/foo", URIMatching: "exact", Method: "GET",
			RequestPurpose: "UNKNOWN", AppID: 1,
		},
	}
	args, _ := json.Marshal(input)
	result, err := ts.createDraftTool(context.Background(), string(args))

	require.NoError(t, err)
	assert.Contains(t, result, "dry-run")
}

func TestCreateDraft_MissingApp(t *testing.T) {
	fakeDB := &database.FakeDatabaseClient{}
	ts := newTestToolSet(t, fakeDB, &fakeSearch{})

	input := CreateDraftInput{
		Content: DraftContent{
			Name: "x", Description: "y", Data: "z", StatusCode: "200",
		},
		Rule: DraftRule{
			URI: "/foo", URIMatching: "exact", Method: "GET",
			RequestPurpose: "UNKNOWN",
		},
	}
	args, _ := json.Marshal(input)
	_, err := ts.createDraftTool(context.Background(), string(args))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "app_id")
}
