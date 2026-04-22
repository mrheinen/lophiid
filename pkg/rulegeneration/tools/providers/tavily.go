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
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"lophiid/pkg/rulegeneration/tools"
	"net/http"
	"time"
)

// TavilySearchProvider implements tools.SearchProvider using the Tavily Search API.
type TavilySearchProvider struct {
	apiKey     string
	httpClient *http.Client
}

// NewTavilySearchProvider creates a new TavilySearchProvider with the given API key and HTTP timeout.
func NewTavilySearchProvider(apiKey string, timeout time.Duration) *TavilySearchProvider {
	return &TavilySearchProvider{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: timeout},
	}
}

type tavilyRequest struct {
	Query       string `json:"query"`
	MaxResults  int    `json:"max_results"`
	SearchDepth string `json:"search_depth"`
}

type tavilyResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Content string `json:"content"`
}

type tavilyResponse struct {
	Results []tavilyResult `json:"results"`
}

// Search performs a web search using the Tavily API.
func (t *TavilySearchProvider) Search(ctx context.Context, query string, maxResults int) ([]tools.SearchResult, error) {
	reqBody := tavilyRequest{
		Query:       query,
		MaxResults:  maxResults,
		SearchDepth: "basic",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling tavily request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tavily.com/search", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating tavily request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.apiKey)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling tavily API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("tavily API returned status %d: %s", resp.StatusCode, string(body))
	}

	var tavilyResp tavilyResponse
	if err := json.NewDecoder(resp.Body).Decode(&tavilyResp); err != nil {
		return nil, fmt.Errorf("decoding tavily response: %w", err)
	}

	results := make([]tools.SearchResult, 0, len(tavilyResp.Results))
	for _, r := range tavilyResp.Results {
		results = append(results, tools.SearchResult{
			Title:   r.Title,
			URL:     r.URL,
			Snippet: r.Content,
		})
	}
	return results, nil
}
