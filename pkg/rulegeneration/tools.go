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
	"io"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const maxExistingRulesLookup = 100
const maxAppsLookup = 500

const maxFetchBodyBytes = 65536

// CreateDraftInput is the JSON payload expected by the create_draft tool.
type CreateDraftInput struct {
	App     *DraftApp    `json:"app,omitempty"`
	Content DraftContent `json:"content"`
	Rule    DraftRule    `json:"rule"`
}

// DraftApp holds the fields for an optional new Application to create.
type DraftApp struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Vendor  string   `json:"vendor"`
	CVES    []string `json:"cves,omitempty"`
	Links   []string `json:"links,omitempty"`
}

// DraftContent holds the fields for the Content to create.
type DraftContent struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Data        string   `json:"data"`
	ContentType string   `json:"content_type,omitempty"`
	Server      string   `json:"server,omitempty"`
	StatusCode  string   `json:"status_code"`
	Headers     []string `json:"headers,omitempty"`
}

// DraftRule holds the fields for the ContentRule to create.
type DraftRule struct {
	URI            string `json:"uri"`
	URIMatching    string `json:"uri_matching"`
	Body           string `json:"body,omitempty"`
	BodyMatching   string `json:"body_matching,omitempty"`
	Method         string `json:"method"`
	RequestPurpose string `json:"request_purpose"`
	AppID          int64  `json:"app_id,omitempty"`
}

// ToolSet holds all dependencies needed by the LLM tool functions.
type ToolSet struct {
	db         database.DatabaseClient
	search     SearchProvider
	httpClient *http.Client
	requestID  int64
	dryRun     bool
	ctx        context.Context
}

// NewToolSet creates a new ToolSet.
func NewToolSet(ctx context.Context, db database.DatabaseClient, search SearchProvider, requestID int64, dryRun bool) *ToolSet {
	return &ToolSet{
		db:         db,
		search:     search,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		requestID:  requestID,
		dryRun:     dryRun,
		ctx:        ctx,
	}
}

// BuildTools returns the full set of LLM tools for the rule generation agent.
func (t *ToolSet) BuildTools() []llm.LLMTool {
	return []llm.LLMTool{
		{
			Name:        "web_search",
			Description: "Search the web for information. Returns titles, URLs and snippets of the top results.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The search query",
					},
				},
				"required": []string{"query"},
			},
			Function: t.webSearchTool,
		},
		{
			Name:        "fetch_url",
			Description: "Fetch the text content of a URL via HTTP GET. Useful for fetching ExploitDB entries, NVD pages, vendor advisories, etc.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{
						"type":        "string",
						"description": "The URL to fetch",
					},
				},
				"required": []string{"url"},
			},
			Function: t.fetchURLTool,
		},
		{
			Name:        "list_existing_rules",
			Description: "List active (non-draft) content rules matching a URI pattern. Use this to check for duplicates before creating a new rule.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"uri_pattern": map[string]any{
						"type":        "string",
						"description": "The URI pattern to search for (partial match)",
					},
				},
				"required": []string{"uri_pattern"},
			},
			Function: t.listExistingRulesTool,
		},
		{
			Name:        "list_apps",
			Description: "List all known applications in the database. Returns app IDs, names, versions, vendors and CVEs. Use this to find an existing app_id or decide if a new app needs to be created.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Function: t.listAppsTool,
		},
		{
			Name: "create_draft",
			Description: `Terminal tool — call this once you have gathered all required information.
Creates a draft Application (if new), Content, and ContentRule in the database.
All records are marked as is_draft=true and enabled=false for human review.
The rule's request_purpose must be one of: ATTACK, RECON, UNKNOWN.`,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{
						"type":        "object",
						"description": "New application to create. Omit if using an existing app_id in the rule.",
						"properties": map[string]any{
							"name":    map[string]any{"type": "string"},
							"version": map[string]any{"type": "string"},
							"vendor":  map[string]any{"type": "string"},
							"cves":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"links":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, // advisory/NVD/exploit URLs
						},
						"required": []string{"name", "version", "vendor"},
					},
					"content": map[string]any{
						"type":        "object",
						"description": "The HTTP response content to serve when the rule matches",
						"properties": map[string]any{
							"name":         map[string]any{"type": "string"},
							"description":  map[string]any{"type": "string"},
							"data":         map[string]any{"type": "string"},
							"content_type": map[string]any{"type": "string"},
							"server":       map[string]any{"type": "string"},
							"status_code":  map[string]any{"type": "string"},
							"headers":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
						},
						"required": []string{"name", "description", "data", "status_code"},
					},
					"rule": map[string]any{
						"type":        "object",
						"description": "The content rule to match incoming requests",
						"properties": map[string]any{
							"uri":             map[string]any{"type": "string"},
							"uri_matching":    map[string]any{"type": "string", "enum": []string{"exact", "prefix", "regex", "contains"}},
							"body":            map[string]any{"type": "string"},
							"body_matching":   map[string]any{"type": "string", "enum": []string{"exact", "prefix", "regex", "contains"}},
							"method":          map[string]any{"type": "string"},
							"request_purpose": map[string]any{"type": "string", "enum": []string{"ATTACK", "RECON", "UNKNOWN"}},
							"app_id":          map[string]any{"type": "integer", "description": "ID of an existing app. Only set if not providing a new app object."},
						},
						"required": []string{"uri", "uri_matching", "method", "request_purpose"},
					},
				},
				"required": []string{"content", "rule"},
			},
			Function: t.createDraftTool,
		},
	}
}

func (t *ToolSet) webSearchTool(args string) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return "", fmt.Errorf("parsing web_search args: %w", err)
	}
	slog.Info("tool: web_search", slog.Int64("request_id", t.requestID), slog.String("query", params.Query))

	results, err := t.search.Search(t.ctx, params.Query, 5)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "web_search"), slog.String("error", err.Error()))
		return "", fmt.Errorf("web search failed: %w", err)
	}

	if len(results) == 0 {
		return "No results found.", nil
	}

	var sb strings.Builder
	for i, r := range results {
		fmt.Fprintf(&sb, "[%d] %s\nURL: %s\n%s\n\n", i+1, r.Title, r.URL, r.Snippet)
	}
	return sb.String(), nil
}

func (t *ToolSet) fetchURLTool(args string) (string, error) {
	var params struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return "", fmt.Errorf("parsing fetch_url args: %w", err)
	}
	slog.Info("tool: fetch_url", slog.Int64("request_id", t.requestID), slog.String("url", params.URL))

	req, err := http.NewRequestWithContext(t.ctx, http.MethodGet, params.URL, nil)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "fetch_url"), slog.String("error", err.Error()))
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; lophiid-agent/1.0)")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "fetch_url"), slog.String("error", err.Error()))
		return "", fmt.Errorf("fetching URL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBodyBytes))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return string(body), nil
}

func (t *ToolSet) listExistingRulesTool(args string) (string, error) {
	var params struct {
		URIPattern string `json:"uri_pattern"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return "", fmt.Errorf("parsing list_existing_rules args: %w", err)
	}

	rules, err := t.db.SearchContentRules(0, maxExistingRulesLookup, fmt.Sprintf("uri:%s enabled:true", params.URIPattern))
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "list_existing_rules"), slog.String("error", err.Error()))
		return "", fmt.Errorf("searching rules: %w", err)
	}

	slog.Info("tool: list_existing_rules",
		slog.Int64("request_id", t.requestID),
		slog.String("pattern", params.URIPattern),
		slog.Int("count", len(rules)))

	if len(rules) == 0 {
		return "No existing rules found for this URI pattern.", nil
	}

	var sb strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&sb, "ID=%d URI=%q method=%s uri_matching=%s\n", r.ID, r.Uri, r.Method, r.UriMatching)
	}
	return sb.String(), nil
}

func (t *ToolSet) listAppsTool(args string) (string, error) {
	apps, err := t.db.SearchApps(0, maxAppsLookup, "")
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "list_apps"), slog.String("error", err.Error()))
		return "", fmt.Errorf("listing apps: %w", err)
	}

	slog.Info("tool: list_apps", slog.Int64("request_id", t.requestID), slog.Int("count", len(apps)))

	if len(apps) == 0 {
		return "No applications found.", nil
	}

	var sb strings.Builder
	for _, a := range apps {
		version := "unknown"
		if a.Version != nil {
			version = *a.Version
		}
		vendor := "unknown"
		if a.Vendor != nil {
			vendor = *a.Vendor
		}
		fmt.Fprintf(&sb, "ID=%d name=%q version=%q vendor=%q cves=%v\n",
			a.ID, a.Name, version, vendor, []string(a.CVES))
	}
	return sb.String(), nil
}

func (t *ToolSet) createDraftTool(args string) (string, error) {
	var input CreateDraftInput
	if err := json.Unmarshal([]byte(args), &input); err != nil {
		return "", fmt.Errorf("parsing create_draft args: %w", err)
	}

	slog.Info("tool: create_draft",
		slog.Int64("request_id", t.requestID),
		slog.String("uri", input.Rule.URI),
		slog.String("method", input.Rule.Method))

	if t.dryRun {
		slog.Info("dry-run: would create draft",
			slog.Int64("request_id", t.requestID),
			slog.String("uri", input.Rule.URI),
			slog.String("method", input.Rule.Method))
		return "dry-run: draft would be created (no DB writes)", nil
	}

	appID, err := t.resolveOrCreateApp(input)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return "", fmt.Errorf("resolving app: %w", err)
	}

	contentID, err := t.createContent(input.Content)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return "", fmt.Errorf("creating content: %w", err)
	}

	ruleID, err := t.createRule(input.Rule, appID, contentID)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return "", fmt.Errorf("creating rule: %w", err)
	}

	slog.Info("draft created",
		slog.Int64("request_id", t.requestID),
		slog.Int64("rule_id", ruleID),
		slog.Int64("content_id", contentID),
		slog.Int64("app_id", appID))

	return fmt.Sprintf("draft created: rule_id=%d content_id=%d app_id=%d", ruleID, contentID, appID), nil
}

func (t *ToolSet) resolveOrCreateApp(input CreateDraftInput) (int64, error) {
	if input.Rule.AppID != 0 {
		return input.Rule.AppID, nil
	}
	if input.App == nil {
		return 0, fmt.Errorf("either rule.app_id or app object must be provided")
	}

	version := input.App.Version
	vendor := input.App.Vendor

	cves := pgtype.FlatArray[string](input.App.CVES)

	links := pgtype.FlatArray[string](input.App.Links)

	app := models.Application{
		Name:    input.App.Name,
		Version: &version,
		Vendor:  &vendor,
		CVES:    cves,
		Links:   links,
		IsDraft: true,
	}

	dm, err := t.db.Insert(&app)
	if err != nil {
		return 0, fmt.Errorf("inserting app: %w", err)
	}
	return dm.ModelID(), nil
}

func (t *ToolSet) createContent(c DraftContent) (int64, error) {
	headers := pgtype.FlatArray[string](c.Headers)

	content := models.Content{
		Name:        c.Name,
		Description: c.Description,
		Data:        models.YammableBytes(c.Data),
		ContentType: c.ContentType,
		Server:      c.Server,
		StatusCode:  c.StatusCode,
		Headers:     headers,
		IsDraft:     true,
	}

	dm, err := t.db.Insert(&content)
	if err != nil {
		return 0, fmt.Errorf("inserting content: %w", err)
	}
	return dm.ModelID(), nil
}

func (t *ToolSet) createRule(r DraftRule, appID, contentID int64) (int64, error) {
	validPurposes := map[string]bool{
		constants.RequestPurposeUnknown: true,
		constants.RequestPurposeRecon:   true,
		constants.RequestPurposeCrawl:   true,
		constants.RequestPurposeAttack:  true,
	}
	validMatchingTypes := map[string]bool{
		constants.MatchingTypeNone:     true,
		constants.MatchingTypeExact:    true,
		constants.MatchingTypePrefix:   true,
		constants.MatchingTypeSuffix:   true,
		constants.MatchingTypeContains: true,
		constants.MatchingTypeRegex:    true,
	}

	uriMatching := r.URIMatching
	if !validMatchingTypes[uriMatching] {
		slog.Warn("createRule: invalid uri_matching, defaulting to none",
			slog.String("got", uriMatching),
			slog.Int64("request_id", t.requestID))
		uriMatching = constants.MatchingTypeNone
	}

	bodyMatching := r.BodyMatching
	if r.Body == "" {
		bodyMatching = constants.MatchingTypeNone
	} else if !validMatchingTypes[bodyMatching] {
		slog.Warn("createRule: invalid body_matching, defaulting to none",
			slog.String("got", bodyMatching),
			slog.Int64("request_id", t.requestID))
		bodyMatching = constants.MatchingTypeNone
	}

	requestPurpose := r.RequestPurpose
	if !validPurposes[requestPurpose] {
		slog.Warn("createRule: invalid request_purpose, defaulting to UNKNOWN",
			slog.String("got", requestPurpose),
			slog.Int64("request_id", t.requestID))
		requestPurpose = constants.RequestPurposeUnknown
	}

	rule := models.ContentRule{
		Uri:              r.URI,
		UriMatching:      uriMatching,
		Body:             r.Body,
		BodyMatching:     bodyMatching,
		Method:           r.Method,
		RequestPurpose:   requestPurpose,
		Responder:        constants.ResponderTypeAuto,
		ResponderDecoder: constants.ResponderDecoderTypeNone,
		AppID:            appID,
		ContentID:        contentID,
		Enabled:          false,
		IsDraft:          true,
	}

	dm, err := t.db.Insert(&rule)
	if err != nil {
		return 0, fmt.Errorf("inserting rule: %w", err)
	}
	return dm.ModelID(), nil
}
