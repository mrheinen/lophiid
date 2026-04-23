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
	"log/slog"
	"strings"

	"github.com/google/go-github/v68/github"
)

// GithubTools holds the dependencies for GitHub-based tool functions.
type GithubTools struct {
	githubClient *github.Client
	maxResults   int
}

// NewGithubTools creates a new GithubTools instance. Pass an empty token to use
// unauthenticated GitHub access (lower rate limits).
func NewGithubTools(token string, maxResults int) *GithubTools {
	var ghClient *github.Client
	if token != "" {
		slog.Info("Using GitHub token for authenticated access")
		ghClient = github.NewClient(nil).WithAuthToken(token)
	} else {
		slog.Warn("Using unauthenticated GitHub access (lower rate limits)")
		ghClient = github.NewClient(nil)
	}
	return &GithubTools{
		githubClient: ghClient,
		maxResults:   maxResults,
	}
}

// SearchGithubCodeTool searches GitHub for exploit proof-of-concepts and related code.
func (t *GithubTools) SearchGithubCodeTool(ctx context.Context, args string) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse tool args", nil), fmt.Errorf("parsing search_github_code args: %w", err)
	}
	slog.Info("tool: search_github_code", slog.String("query", params.Query))

	opts := &github.SearchOptions{
		ListOptions: github.ListOptions{PerPage: t.maxResults},
	}
	results, _, err := t.githubClient.Search.Code(ctx, params.Query, opts)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "search_github_code"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Failed to search GitHub for code", nil), fmt.Errorf("GitHub code search failed: %w", err)
	}

	if results.GetTotal() == 0 {
		return GetJSONSuccessMessage("No results found", nil), nil
	}

	var sb strings.Builder
	for _, r := range results.CodeResults {
		htmlURL := r.GetHTMLURL()
		rawURL := strings.Replace(htmlURL, "https://github.com", "https://raw.githubusercontent.com", 1)
		rawURL = strings.Replace(rawURL, "/blob/", "/", 1)
		fmt.Fprintf(&sb, "%s\n", rawURL)
	}
	return GetJSONSuccessMessage("Found results", sb.String()), nil
}
