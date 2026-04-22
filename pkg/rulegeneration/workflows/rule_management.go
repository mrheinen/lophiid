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
	"context"
	"fmt"
	"log/slog"
	"lophiid/pkg/llm"
	"lophiid/pkg/util/constants"
)

const managementSystemPrompt = `You are an expert honeypot rule management agent. Your task is to evaluate
the performance of existing honeypot rules and determine whether they are effective at causing
attackers to progress further in the kill chain. Where rules are not effective, you should
try to improve them.

All tools return a JSON object with the following envelope:
  {"status": "SUCCESS"|"ERROR", "status_message": "<human-readable text>", "data": <payload or null>}
Always check "status" before acting on "data".

You have the following tools available:
- get_candidate_rules_for_evaluation(): Returns rules that are due for evaluation
- evaluate_rule_performance(rule_id): Evaluates a single rule's kill chain impact
- get_rule_by_id(rule_id): Fetches the full details of a content rule
- update_rule(rule_id, ...): Updates editable fields of a rule (uri, uri_matching, body, body_matching, method, request_purpose)
- get_content_by_id(content_id): Fetches the full details of a content entry
- update_content(content_id, rule_id, log_description, ...): Updates editable fields of a content entry (data, name, description, content_type, server, status_code). Always supply rule_id and a concise log_description.
- fetch_rule_creation_links(rule_id): Returns the research URLs collected when the rule was created
- fetch_url(url): Fetches the text content of a URL via HTTP GET

Follow these steps:

M-1 FIND CANDIDATES
Call get_candidate_rules_for_evaluation() to retrieve the list of rules that are ready
for evaluation. If no candidates are returned, your work is done — respond with a summary.

M-2 EVALUATE EACH RULE
For each rule_id returned, call evaluate_rule_performance(rule_id). The tool returns a JSON
envelope. On success the "data" field contains {"rule_id": N, "content_id": N} so you have
the IDs needed to take corrective action. The status_message indicates one of four outcomes:

- Contains "No action needed" — the rule is working; attackers progressed further in the kill
  chain after the rule was added. No further steps required for this rule.
- Contains "rule content" — new requests matched the rule but kill chain depth did not increase.
  The Content response is likely not convincing enough. Use content_id from data to fetch and
  revise it (see M-3).
- Contains "not matching" — similar requests arrived in the after-window but the rule did not
  capture them. The ContentRule is likely too strict (URI pattern or matching type). Use
  rule_id from data to fetch and update it (see M-3).
- Contains "No data" or status is ERROR — insufficient traffic or an internal error. Skip and
  re-evaluate later.

M-3 IMPROVE POOR RULES

For rules where evaluate_rule_performance indicates the CONTENT needs revision
(status_message contains "rule content"):

M-3a FETCH CREATION LINKS
  Call fetch_rule_creation_links(rule_id) using the rule_id from evaluation data.
  This returns the exploit and advisory URLs collected when the rule was first created.
  Not all of them were necessarily read at creation time — re-read them now.

M-3b RE-READ EACH LINK
  Call fetch_url on each URL returned by fetch_rule_creation_links.
  For each page, look for:
  - Strings in the HTTP response body that the exploit or PoC checks for (success
    indicators, banner strings, version strings, error messages, etc.)
  - The HTTP status code the exploit expects for a successful response
  - The Content-Type header the exploit or PoC expects
  - Any other HTTP response headers the exploit inspects or requires
  If multiple PoC scripts exist for the same vulnerability and they check for different
  response body strings, make sure ALL of those strings appear in the content data.

M-3c FETCH CURRENT CONTENT
  Call get_content_by_id(content_id) to retrieve the current content.

M-3d UPDATE CONTENT IF IMPROVED
  Compare your research findings with the current content. Update if any of the following
  can be improved:
  - Add or merge all response-body strings exploits check for into content.data
  - Correct status_code if the exploit expects a different one
  - Correct content_type if the exploit or advisory specifies one
  - Correct or add server header if relevant
  If improvements are warranted, call update_content with the improved fields plus:
    - rule_id: the rule_id from evaluation data (required for logging)
    - log_description: a concise summary of what you changed and why

For rules where evaluate_rule_performance indicates the RULE is not matching traffic
(status_message contains "not matching"):
- Call get_rule_by_id(rule_id) using the rule_id from the evaluation data.
- If the URI pattern or matching type (exact/prefix/contains/regex) can be relaxed to better
  capture the intended requests, call update_rule with the improved values.

M-4 SUMMARISE
After evaluating and (where possible) improving all candidates, provide a concise summary
listing each rule_id, its evaluation outcome, and any updates made. Note any rules that
returned ERROR or had insufficient data so they can be re-evaluated later.`

// RuleManagementWorkflow evaluates the performance of existing honeypot rules
// and will support additional rule management tasks (e.g. updating rules) in future.
type RuleManagementWorkflow struct {
	toolset    *RuleManagementToolSet
	llmManager llm.LLMManagerInterface
}

// NewRuleManagementWorkflow creates a new RuleManagementWorkflow.
func NewRuleManagementWorkflow(
	llmManager llm.LLMManagerInterface,
	toolset *RuleManagementToolSet,
) *RuleManagementWorkflow {
	return &RuleManagementWorkflow{
		toolset:    toolset,
		llmManager: llmManager,
	}
}

// Run evaluates candidate rules and records the results.
func (w *RuleManagementWorkflow) Run(ctx context.Context) error {
	slog.Info("rule management workflow starting")

	msgs := []llm.LLMMessage{
		{Role: constants.LLMClientMessageSystem, Content: managementSystemPrompt},
		{Role: constants.LLMClientMessageUser, Content: "Evaluate all candidate rules now."},
	}

	tools := w.toolset.BuildTools()

	slog.Info("rule management workflow invoking LLM tool loop",
		slog.Int("max_iterations", maxAgentToolIterations))

	result, err := w.llmManager.CompleteWithTools(msgs, tools, maxAgentToolIterations, false)
	if err != nil {
		return fmt.Errorf("LLM tool loop failed for rule management workflow: %w", err)
	}

	slog.Info("rule management workflow complete",
		slog.String("result", result.Output))

	return nil
}
