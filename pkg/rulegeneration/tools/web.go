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
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const maxFetchBodyBytes = 65536

// WebTools holds the dependencies for web-based tool functions.
type WebTools struct {
	httpClient *http.Client
	search     SearchProvider
}

// NewWebTools creates a new WebTools instance.
func NewWebTools(search SearchProvider) *WebTools {
	return &WebTools{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		search:     search,
	}
}

// WebSearchTool searches the web for information.
func (t *WebTools) WebSearchTool(ctx context.Context, args string) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse tool args", nil), fmt.Errorf("parsing web_search args: %w", err)
	}
	slog.Info("tool: web_search", slog.String("query", params.Query))

	results, err := t.search.Search(ctx, params.Query, 5)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "web_search"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Failed to search the web", nil), fmt.Errorf("web search failed: %w", err)
	}

	if len(results) == 0 {
		return GetJSONSuccessMessage("No results found", nil), nil
	}

	var sb strings.Builder
	for i, r := range results {
		fmt.Fprintf(&sb, "[%d] %s\nURL: %s\n%s\n\n", i+1, r.Title, r.URL, r.Snippet)
	}
	return GetJSONSuccessMessage("Found results", sb.String()), nil
}

// FetchURLTool fetches the text content of a URL via HTTP GET.
func (t *WebTools) FetchURLTool(ctx context.Context, args string) (string, error) {
	var params struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse tool args", nil), fmt.Errorf("parsing fetch_url args: %w", err)
	}
	slog.Info("tool: fetch_url", slog.String("url", params.URL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, params.URL, nil)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "fetch_url"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Failed to create the HTTP request", nil), fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; lophiid-agent/1.0)")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "fetch_url"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("A failure occured while fetching the URL", nil), fmt.Errorf("fetching URL: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBodyBytes))
	if err != nil {
		return GetJSONErrorMessage("A failure occured while reading the HTTP response", nil), fmt.Errorf("reading response: %w", err)
	}
	return GetJSONSuccessMessage("Successfully fetched the URL", string(body)), nil
}
