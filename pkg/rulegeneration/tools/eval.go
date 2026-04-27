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
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
	"lophiid/pkg/util/constants"
	"net/url"
	"strings"
	"time"
)

const maxCandidateRulesForEval = 20
const maxWindowRequestsCount = 1000

// sessionIDRow is used to scan SELECT DISTINCT session_id results.
type sessionIDRow struct {
	SessionID int64 `ksql:"session_id"`
}

// RequestCountRow is used to scan COUNT(*) results.
type RequestCountRow struct {
	Count int `ksql:"count"`
}

// evalResultData carries the rule and content IDs the management agent needs to
// take corrective action without issuing additional tool calls.
type evalResultData struct {
	RuleID    int64 `json:"rule_id"`
	ContentID int64 `json:"content_id"`
}

// EvalTools holds the dependencies for rule evaluation tool functions.
type EvalTools struct {
	db                    database.DatabaseClient
	evaluationWindow      time.Duration
	maxEvalSessions       int
	evalProgressThreshold float64
	maxLinksPerDomain     int
	maxTotalLinks         int
}

// NewEvalTools creates a new EvalTools instance.
func NewEvalTools(db database.DatabaseClient, evaluationWindow time.Duration, maxEvalSessions int, evalProgressThreshold float64, maxLinksPerDomain int, maxTotalLinks int) *EvalTools {
	return &EvalTools{
		db:                    db,
		evaluationWindow:      evaluationWindow,
		maxEvalSessions:       maxEvalSessions,
		evalProgressThreshold: evalProgressThreshold,
		maxLinksPerDomain:     maxLinksPerDomain,
		maxTotalLinks:         maxTotalLinks,
	}
}

// GetCandidateRulesForEvaluationTool returns rule IDs of RULE_AGENT-sourced rules
// that have been approved and whose last evaluation is older than the evaluation window.
func (t *EvalTools) GetCandidateRulesForEvaluationTool(_ context.Context, _ string) (string, error) {
	cutoff := time.Now().UTC().Add(-t.evaluationWindow)
	query := fmt.Sprintf("source:%s !approved_at: last_evaluated_at<%s",
		constants.SourceTypeRuleAgent,
		cutoff.Format(time.RFC3339))

	rules, err := t.db.SearchContentRules(0, maxCandidateRulesForEval, query)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "get_candidate_rules_for_evaluation"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Error while searching candidate rules", nil), fmt.Errorf("searching candidate rules: %w", err)
	}

	slog.Info("tool: get_candidate_rules_for_evaluation",
		slog.Int("count", len(rules)))

	if len(rules) == 0 {
		return GetJSONSuccessMessage("No candidate rules found.", nil), nil
	}

	var sb strings.Builder
	for _, r := range rules {
		approvedAt := ""
		if r.ApprovedAt != nil {
			approvedAt = r.ApprovedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(&sb, "rule_id=%d approved_at=%s last_evaluated_at=%s\n",
			r.ID, approvedAt, r.LastEvaluatedAt.Format(time.RFC3339))
	}
	return GetJSONSuccessMessage("Found candidate rules", sb.String()), nil
}

// EvaluateRulePerformanceTool evaluates whether a rule caused attackers to progress
// further in the kill chain by comparing kill chains before and after the rule's approval date.
func (t *EvalTools) EvaluateRulePerformanceTool(_ context.Context, args string) (string, error) {
	var params struct {
		RuleID int64 `json:"rule_id"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse tool args", nil), fmt.Errorf("parsing evaluate_rule_performance args: %w", err)
	}

	slog.Info("tool: evaluate_rule_performance", slog.Int64("rule_id", params.RuleID))

	rules, err := t.db.SearchContentRules(0, 1, fmt.Sprintf("id:%d", params.RuleID))
	if err != nil {
		return GetJSONErrorMessage("Error while searching rule", nil), fmt.Errorf("fetching rule %d: %w", params.RuleID, err)
	}
	if len(rules) == 0 {
		return GetJSONErrorMessage("Rule not found", nil), fmt.Errorf("rule %d not found", params.RuleID)
	}
	rule := rules[0]

	// It's almost crazy to keep this check but I think it will bring bad luck to remove it.
	// Anyway, we already don't select rules without an approved_at timestamp in the search query.
	if rule.ApprovedAt == nil {
		return GetJSONErrorMessage("Rule has no approved_at timestamp", nil), nil
	}

	approvedAt := *rule.ApprovedAt
	resultData := evalResultData{RuleID: rule.ID, ContentID: rule.ContentID}

	// The before window encompasses the situation before we created the new rule. Here you typically
	// will only see one step in each kill chain (e.g., only the initial request, not the follow-up).
	beforeStart := approvedAt.Add(-t.evaluationWindow)
	beforeEnd := approvedAt
	// The after window is the time after we approved the rule. This is where we expect to see more
	// advanced kill chains if the rule is effective.
	afterStart := approvedAt
	afterEnd := approvedAt.Add(t.evaluationWindow)

	afterQuery := fmt.Sprintf("rule_id:%d time_received>%s time_received<%s",
		params.RuleID,
		afterStart.Format(time.RFC3339),
		afterEnd.Format(time.RFC3339))
	afterReqs, err := t.db.SearchRequests(0, maxWindowRequestsCount, afterQuery)
	if err != nil {
		return GetJSONErrorMessage("Error while searching after-window requests", nil), fmt.Errorf("fetching after-window requests: %w", err)
	}

	if len(afterReqs) >= maxWindowRequestsCount {
		slog.Warn("after-window requests limit reached", slog.Int64("rule_id", params.RuleID), slog.Int("count", len(afterReqs)))
	}

	afterHashes := make([]string, 0)
	afterSessionSet := make(map[int64]struct{})
	seenHashes := make(map[string]struct{})
	for _, req := range afterReqs {
		if _, seen := seenHashes[req.BaseHash]; !seen && req.BaseHash != "" {
			afterHashes = append(afterHashes, req.BaseHash)
			seenHashes[req.BaseHash] = struct{}{}
		}
		afterSessionSet[req.SessionID] = struct{}{}
	}

	if len(afterHashes) == 0 {
		slog.Info("evaluate_rule_performance: no rule matches in after-window", slog.Int64("rule_id", params.RuleID))
		if err := t.updateLastEvaluatedAt(&rule); err != nil {
			slog.Warn("failed to update last_evaluated_at", slog.Int64("rule_id", rule.ID), slog.String("error", err.Error()))
		}

		// Case 2: no rule matches in the after-window. Look up the RULE_CREATION log
		// entry to find the originating request, use its base_hash to check whether
		// similar requests arrived in the after-window without being captured.
		var logRows []models.RuleManagementLog
		logQuery := "SELECT request_id FROM rule_management_log WHERE rule_id = $1 AND type = $2 LIMIT 1"
		if _, lErr := t.db.ParameterizedQuery(logQuery, &logRows, rule.ID, constants.RuleManagementLogTypeCreation); lErr == nil && len(logRows) > 0 && logRows[0].RequestID != nil {
			baseReq, rErr := t.db.GetRequestByID(*logRows[0].RequestID)
			if rErr == nil {
				var counts []RequestCountRow
				cntCmpQuery := "SELECT COUNT(*) AS count FROM request WHERE cmp_hash = $1 AND time_received >= $2 AND time_received < $3"
				if _, cErr := t.db.ParameterizedQuery(cntCmpQuery, &counts, baseReq.CmpHash, afterStart, afterEnd); cErr == nil && len(counts) > 0 && counts[0].Count > 0 {
					slog.Info("evaluate_rule_performance: based on cmp_hash. requests present but rule did not match",
						slog.Int64("rule_id", params.RuleID),
						slog.Int("similar_count", counts[0].Count))
					return GetJSONSuccessMessage("Rule not matching: requests that should have matched the rule occurred in the after-window but the rule did not capture them. The content rule must be updated.", resultData), nil
				}

				cntQuery := "SELECT COUNT(*) AS count FROM request WHERE base_hash = $1 AND time_received >= $2 AND time_received < $3"
				if _, cErr := t.db.ParameterizedQuery(cntQuery, &counts, baseReq.BaseHash, afterStart, afterEnd); cErr == nil && len(counts) > 0 && counts[0].Count > 0 {
					slog.Info("evaluate_rule_performance: roughly similar requests present but rule did not match",
						slog.Int64("rule_id", params.RuleID),
						slog.Int("similar_count", counts[0].Count))
					return GetJSONSuccessMessage("Rule not matching: roughly similar requests, occurred in the after-window but the rule did not capture them. The content rule may be too strict and may need updating.", resultData), nil
				}
			}
		}

		return GetJSONSuccessMessage("No data: no similar traffic observed in the evaluation window.", nil), nil
	}

	var beforeRows []sessionIDRow
	beforeQuery := "SELECT DISTINCT session_id FROM request WHERE base_hash = ANY($1) AND time_received >= $2 AND time_received < $3 LIMIT $4"
	if _, err := t.db.ParameterizedQuery(beforeQuery, &beforeRows, afterHashes, beforeStart, beforeEnd, t.maxEvalSessions); err != nil {
		return GetJSONErrorMessage("Database error while searching before-window session IDs", nil), fmt.Errorf("fetching before-window session IDs: %w", err)
	}

	if len(beforeRows) >= t.maxEvalSessions {
		slog.Warn("before-window session limit reached", slog.Int64("rule_id", params.RuleID), slog.Int("count", len(beforeRows)))
	}

	beforeSessionIDs := make([]int64, len(beforeRows))
	for i, r := range beforeRows {
		beforeSessionIDs[i] = r.SessionID
	}
	afterSessionIDs := util.MapKeysToSlice(afterSessionSet, t.maxEvalSessions)

	var beforeKCs []models.KillChain
	kcQuery := "SELECT * FROM kill_chain WHERE session_id = ANY($1) AND started_at >= $2 AND ended_at < $3 LIMIT $4"
	if _, err := t.db.ParameterizedQuery(kcQuery, &beforeKCs, beforeSessionIDs, beforeStart, beforeEnd, t.maxEvalSessions); err != nil {
		return GetJSONErrorMessage("Database error while searching before kill chains", nil), fmt.Errorf("fetching before kill chains: %w", err)
	}

	var afterKCs []models.KillChain
	if _, err := t.db.ParameterizedQuery(kcQuery, &afterKCs, afterSessionIDs, afterStart, afterEnd, t.maxEvalSessions); err != nil {
		return GetJSONErrorMessage("Database error while searching after kill chains", nil), fmt.Errorf("fetching after kill chains: %w", err)
	}

	if len(beforeKCs) == 0 || len(afterKCs) == 0 {
		if err := t.updateLastEvaluatedAt(&rule); err != nil {
			slog.Warn("failed to update last_evaluated_at", slog.Int64("rule_id", rule.ID), slog.String("error", err.Error()))
		}
		return GetJSONSuccessMessage("Insufficient kill chain data in one or both windows", nil), nil
	}

	var sumDepthBefore float64
	var sumCountBefore float64

	for _, kc := range beforeKCs {
		sumDepthBefore += float64(kc.MaxPhaseDepth)
		sumCountBefore += float64(kc.PhaseCount)
	}
	baselineDepth := sumDepthBefore / float64(len(beforeKCs))
	baselineCount := sumCountBefore / float64(len(beforeKCs))

	var deepBefore, deepAfter, countBefore, countAfter int

	for _, kc := range beforeKCs {
		if float64(kc.MaxPhaseDepth) > baselineDepth {
			deepBefore++
		}
		if float64(kc.PhaseCount) > baselineCount {
			countBefore++
		}
	}
	for _, kc := range afterKCs {
		if float64(kc.MaxPhaseDepth) > baselineDepth {
			deepAfter++
		}
		if float64(kc.PhaseCount) > baselineCount {
			countAfter++
		}
	}

	fractionDeepBefore := float64(deepBefore) / float64(len(beforeKCs))
	fractionDeepAfter := float64(deepAfter) / float64(len(afterKCs))
	fractionCountBefore := float64(countBefore) / float64(len(beforeKCs))
	fractionCountAfter := float64(countAfter) / float64(len(afterKCs))

	progressedDepth := (fractionDeepAfter - fractionDeepBefore) > t.evalProgressThreshold
	progressedCount := (fractionCountAfter - fractionCountBefore) > t.evalProgressThreshold
	progressed := progressedDepth || progressedCount

	if err := t.updateLastEvaluatedAt(&rule); err != nil {
		slog.Warn("failed to update last_evaluated_at", slog.Int64("rule_id", rule.ID), slog.String("error", err.Error()))
	}

	slog.Info("evaluate_rule_performance result",
		slog.Int64("rule_id", params.RuleID),
		slog.Int("before_kcs", len(beforeKCs)),
		slog.Float64("baseline_depth", baselineDepth),
		slog.Float64("baseline_count", baselineCount),
		slog.Float64("depth_fraction_before", fractionDeepBefore),
		slog.Float64("depth_fraction_after", fractionDeepAfter),
		slog.Float64("count_fraction_before", fractionCountBefore),
		slog.Float64("count_fraction_after", fractionCountAfter),
		slog.Float64("threshold", t.evalProgressThreshold),
		slog.Bool("progressed", progressed),
	)

	if progressed {
		return GetJSONSuccessMessage("Rule is effective: attackers progressed further into the kill chain after the rule was added. No action needed.", resultData), nil
	}
	return GetJSONSuccessMessage("Rule not effective: new requests matched the rule but attackers did not progress further in the kill chain. The rule content may need to be revised to provide a more convincing response.", resultData), nil
}

// updateLastEvaluatedAt sets the rule's LastEvaluatedAt to the current UTC time.
func (t *EvalTools) updateLastEvaluatedAt(rule *models.ContentRule) error {
	rule.LastEvaluatedAt = time.Now().UTC()
	return t.db.Update(rule)
}

// FetchRuleCreationLinksTool returns the research links stored in the
// RULE_CREATION management log entry for the given rule.  The list is capped
// to at most maxLinksPerDomain URLs per hostname and maxTotalLinks total, so
// the LLM receives a focused, bounded set of URLs to re-read.
func (t *EvalTools) FetchRuleCreationLinksTool(_ context.Context, args string) (string, error) {
	var params struct {
		RuleID int64 `json:"rule_id"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse tool args", nil), fmt.Errorf("parsing fetch_rule_creation_links args: %w", err)
	}
	if params.RuleID == 0 {
		return GetJSONErrorMessage("A rule_id is required and it cannot be 0", nil), nil
	}

	slog.Info("tool: fetch_rule_creation_links", slog.Int64("rule_id", params.RuleID))

	var logRows []models.RuleManagementLog
	query := "SELECT related_links FROM rule_management_log WHERE rule_id = $1 AND type = $2 LIMIT 1"
	if _, err := t.db.ParameterizedQuery(query, &logRows, params.RuleID, constants.RuleManagementLogTypeCreation); err != nil {
		slog.Error("tool error", slog.String("tool_name", "fetch_rule_creation_links"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Database error fetching creation log", nil), fmt.Errorf("querying rule_management_log: %w", err)
	}

	if len(logRows) == 0 {
		return GetJSONSuccessMessage("No links found for this rule.", []string{}), nil
	}
	stored := []string(logRows[0].RelatedLinks)
	if len(stored) == 0 {
		return GetJSONSuccessMessage("No links found for this rule.", []string{}), nil
	}

	filtered := filterLinks(stored, t.maxLinksPerDomain, t.maxTotalLinks)

	slog.Info("tool: fetch_rule_creation_links result",
		slog.Int64("rule_id", params.RuleID),
		slog.Int("total_stored", len(stored)),
		slog.Int("returned", len(filtered)))

	return GetJSONSuccessMessage(fmt.Sprintf("%d links returned", len(filtered)), filtered), nil
}

// filterLinks applies per-domain and total caps to a list of URLs.
// Malformed URLs are dropped silently.
func filterLinks(links []string, maxPerDomain, maxTotal int) []string {
	domainCount := make(map[string]int)
	out := make([]string, 0, maxTotal)
	for _, raw := range links {
		if len(out) >= maxTotal {
			break
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Hostname()
		if domainCount[host] >= maxPerDomain {
			continue
		}
		domainCount[host]++
		out = append(out, raw)
	}
	return out
}
