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

// RuleManagementToolSet composes the tool implementations needed by the rule
// management workflow and exposes them as a set of LLM tools.
type RuleManagementToolSet struct {
	evalTools     *tools.EvalTools
	databaseTools *tools.DatabaseTools
	webTools      *tools.WebTools
}

// NewRuleManagementToolSet creates a new RuleManagementToolSet.
func NewRuleManagementToolSet(
	evalTools *tools.EvalTools,
	databaseTools *tools.DatabaseTools,
	webTools *tools.WebTools,
) *RuleManagementToolSet {
	return &RuleManagementToolSet{
		evalTools:     evalTools,
		databaseTools: databaseTools,
		webTools:      webTools,
	}
}

// BuildTools returns the LLM tool definitions for the rule management workflow.
func (ts *RuleManagementToolSet) BuildTools() []llm.LLMTool {
	return []llm.LLMTool{
		{
			Name:        "get_candidate_rules_for_evaluation",
			Description: "Returns rule IDs of RULE_AGENT-sourced rules that have been approved and whose last evaluation is older than the evaluation window. Call this to find rules that are ready to be evaluated.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Function: ts.evalTools.GetCandidateRulesForEvaluationTool,
		},
		{
			Name:        "evaluate_rule_performance",
			Description: "Evaluates whether a rule caused attackers to progress further in the kill chain by comparing kill chains before and after the rule's approval date. Returns a JSON object with status (SUCCESS, ERROR, NO_DATA), progressed (bool), and details.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "integer",
						"description": "The ID of the rule to evaluate",
					},
				},
				"required": []string{"rule_id"},
			},
			Function: ts.evalTools.EvaluateRulePerformanceTool,
		},
		{
			Name:        "get_rule_by_id",
			Description: "Fetches an existing content rule by its ID and returns it as JSON.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "integer",
						"description": "The ID of the rule to fetch",
					},
				},
				"required": []string{"rule_id"},
			},
			Function: ts.databaseTools.GetRuleByIDTool,
		},
		{
			Name:        "update_rule",
			Description: "Updates editable fields of an existing content rule. Only the fields included in the call are changed; omitted fields are left as-is. Editable fields: uri, uri_matching, body, body_matching, method, request_purpose.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "integer",
						"description": "The ID of the rule to update",
					},
					"uri": map[string]any{
						"type":        "string",
						"description": "New URI pattern",
					},
					"uri_matching": map[string]any{
						"type":        "string",
						"description": "URI matching type: exact, prefix, suffix, contains, regex, or none",
					},
					"body": map[string]any{
						"type":        "string",
						"description": "New body matching pattern",
					},
					"body_matching": map[string]any{
						"type":        "string",
						"description": "Body matching type: exact, prefix, suffix, contains, regex, or none",
					},
					"method": map[string]any{
						"type":        "string",
						"description": "HTTP method (e.g. GET, POST)",
					},
					"request_purpose": map[string]any{
						"type":        "string",
						"description": "Kill chain purpose: UNKNOWN, RECON, VERIFY, EXPLOITATION, or CLEANUP",
					},
				},
				"required": []string{"rule_id"},
			},
			Function: ts.databaseTools.UpdateRuleTool,
		},
		{
			Name:        "get_content_by_id",
			Description: "Fetches an existing content entry by its ID and returns it as JSON.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"content_id": map[string]any{
						"type":        "integer",
						"description": "The ID of the content to fetch",
					},
				},
				"required": []string{"content_id"},
			},
			Function: ts.databaseTools.GetContentByIDTool,
		},
		{
			Name:        "update_content",
			Description: "Updates editable fields of an existing content entry. Only the fields included in the call are changed; omitted fields are left as-is. Editable fields: data, name, description, content_type, server, status_code.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"content_id": map[string]any{
						"type":        "integer",
						"description": "The ID of the content to update",
					},
					"data": map[string]any{
						"type":        "string",
						"description": "New content body data",
					},
					"name": map[string]any{
						"type":        "string",
						"description": "New content name",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "New content description",
					},
					"content_type": map[string]any{
						"type":        "string",
						"description": "New HTTP Content-Type header value",
					},
					"server": map[string]any{
						"type":        "string",
						"description": "New HTTP Server header value",
					},
					"status_code": map[string]any{
						"type":        "string",
						"description": "New HTTP status code (e.g. 200, 404)",
					},
					"rule_id": map[string]any{
						"type":        "integer",
						"description": "The rule this content belongs to. Provide so the update is recorded in the management log.",
					},
					"log_description": map[string]any{
						"type":        "string",
						"description": "Brief description of what was changed and why (used for the management log entry).",
					},
				},
				"required": []string{"content_id"},
			},
			Function: ts.databaseTools.UpdateContentTool,
		},
		{
			Name:        "fetch_rule_creation_links",
			Description: "Returns the research URLs that were collected when the rule was created (from its RULE_CREATION log entry). Use this before improving content so you can re-read the original exploit sources. The list is pre-filtered to a sensible size.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"rule_id": map[string]any{
						"type":        "integer",
						"description": "The rule ID whose creation links to fetch",
					},
				},
				"required": []string{"rule_id"},
			},
			Function: ts.evalTools.FetchRuleCreationLinksTool,
		},
		{
			Name:        "fetch_url",
			Description: "Fetches the text content of a URL via HTTP GET and returns the body. Use this to re-read exploit references, PoC scripts, or advisory pages.",
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
	}
}
