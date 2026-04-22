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
package workflows

import (
	"lophiid/pkg/llm"
	"lophiid/pkg/rulegeneration/tools"
)

// RuleCreationToolSet composes the tool implementations needed by the rule
// creation workflow and exposes them as a set of LLM tools.
type RuleCreationToolSet struct {
	webTools      *tools.WebTools
	githubTools   *tools.GithubTools
	databaseTools *tools.DatabaseTools
}

// NewRuleCreationToolSet creates a new RuleCreationToolSet.
func NewRuleCreationToolSet(
	webTools *tools.WebTools,
	githubTools *tools.GithubTools,
	databaseTools *tools.DatabaseTools,
) *RuleCreationToolSet {
	return &RuleCreationToolSet{
		webTools:      webTools,
		githubTools:   githubTools,
		databaseTools: databaseTools,
	}
}

// BuildTools returns the LLM tool definitions for the rule creation workflow.
func (ts *RuleCreationToolSet) BuildTools() []llm.LLMTool {
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
			Function: ts.webTools.WebSearchTool,
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
			Function: ts.webTools.FetchURLTool,
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
			Function: ts.databaseTools.ListExistingRulesTool,
		},
		{
			Name:        "list_apps",
			Description: "List all known applications in the database. Returns app IDs, names, versions, vendors and CVEs. Use this to find an existing app_id or decide if a new app needs to be created.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Function: ts.databaseTools.ListAppsTool,
		},
		{
			Name:        "search_github_code",
			Description: "Search GitHub for exploit proof-of-concepts and related code. Returns up to 5 raw file URLs pointing to matching files. Use fetch_url on each result to inspect the content.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "The GitHub code search query, e.g. \" /scriptText CVE\"",
					},
				},
				"required": []string{"query"},
			},
			Function: ts.githubTools.SearchGithubCodeTool,
		},
		{
			Name: "create_draft",
			Description: `Terminal tool — call this once you have gathered all required information.
Creates a draft Application (if new), Content, and ContentRule in the database.
All records are marked as is_draft=true and enabled=false for human review.
The rule's request_purpose must be one of: EXPLOITATION, RECON, UNKNOWN.`,
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
							"links":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
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
					"description": map[string]any{
						"type":        "string",
						"description": "Concise human-readable summary of what was found and why this rule was created (e.g. CVE ID, application name, attack type)",
					},
					"links": map[string]any{
						"type":        "array",
						"description": "Complete list of every research URL accumulated during the workflow (ExploitDB, GitHub PoC, analysis pages, NVD, vendor advisories). Always provide this — it is stored in the rule management log regardless of whether a new app is created.",
						"items":       map[string]any{"type": "string"},
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
							"request_purpose": map[string]any{"type": "string", "enum": []string{"EXPLOITATION", "RECON", "UNKNOWN"}},
							"app_id":          map[string]any{"type": "integer", "description": "ID of an existing app. Only set if not providing a new app object."},
						},
						"required": []string{"uri", "uri_matching", "method", "request_purpose"},
					},
				},
				"required": []string{"content", "rule", "description"},
			},
			Function: ts.databaseTools.CreateDraftTool,
		},
	}
}
