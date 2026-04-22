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
	"errors"
	"fmt"
	"log/slog"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util/constants"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vingarcia/ksql"
)

const maxExistingRulesLookup = 100
const maxAppsLookup = 500

// DatabaseTools holds the dependencies for database-related tool functions.
type DatabaseTools struct {
	db     database.DatabaseClient
	dryRun bool
}

// NewDatabaseTools creates a new DatabaseTools instance.
func NewDatabaseTools(db database.DatabaseClient, dryRun bool) *DatabaseTools {
	return &DatabaseTools{
		db:     db,
		dryRun: dryRun,
	}
}

// ListExistingRulesTool lists active (non-draft) content rules matching a URI pattern.
func (t *DatabaseTools) ListExistingRulesTool(_ context.Context, args string) (string, error) {
	var params struct {
		URIPattern string `json:"uri_pattern"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing list_existing_rules args: %w", err)
	}

	rules, err := t.db.SearchContentRules(0, maxExistingRulesLookup, fmt.Sprintf("uri:%s enabled:true", params.URIPattern))
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "list_existing_rules"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Failed to list existing rules", nil), fmt.Errorf("searching rules: %w", err)
	}

	slog.Info("tool: list_existing_rules",
		slog.String("pattern", params.URIPattern),
		slog.Int("count", len(rules)))

	if len(rules) == 0 {
		return GetJSONSuccessMessage("No existing rules found for this URI pattern.", nil), nil
	}

	var sb strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&sb, "ID=%d URI=%q method=%s uri_matching=%s\n", r.ID, r.Uri, r.Method, r.UriMatching)
	}
	return GetJSONSuccessMessage("Found rules", sb.String()), nil
}

// ListAppsTool lists all known applications in the database.
func (t *DatabaseTools) ListAppsTool(_ context.Context, args string) (string, error) {
	apps, err := t.db.SearchApps(0, maxAppsLookup, "")
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "list_apps"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("listing apps: %w", err)
	}

	slog.Info("tool: list_apps", slog.Int("count", len(apps)))

	if len(apps) == 0 {
		return GetJSONSuccessMessage("No applications found.", nil), nil
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
	return GetJSONSuccessMessage("here are the apps", sb.String()), nil
}

// CreateDraftTool creates a draft Application (if new), Content, and ContentRule in the database.
func (t *DatabaseTools) CreateDraftTool(_ context.Context, args string) (string, error) {
	var input CreateDraftInput
	if err := json.Unmarshal([]byte(args), &input); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing create_draft args: %w, %s", err, args)
	}

	slog.Info("tool: create_draft",
		slog.String("uri", input.Rule.URI),
		slog.String("method", input.Rule.Method))

	if t.dryRun {
		slog.Info("dry-run: would create draft",
			slog.String("uri", input.Rule.URI),
			slog.String("method", input.Rule.Method))
		return GetJSONSuccessMessage("dry-run mode: draft would be created (no DB writes)", nil), nil
	}

	appID, err := t.resolveOrCreateApp(input)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("unable to create/resolve app", nil), fmt.Errorf("resolving app: %w", err)
	}

	contentID, err := t.createContent(input.Content)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("unable to create content", nil), fmt.Errorf("creating content: %w", err)
	}

	ruleID, err := t.createRule(input.Rule, appID, contentID)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "create_draft"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("unable to create rule", nil), fmt.Errorf("creating rule: %w", err)
	}

	slog.Info("draft created",
		slog.Int64("rule_id", ruleID),
		slog.Int64("content_id", contentID),
		slog.Int64("app_id", appID))

	t.writeCreationLog(input, ruleID)

	return GetJSONSuccessMessage("draft created", fmt.Sprintf("draft created: rule_id=%d content_id=%d app_id=%d", ruleID, contentID, appID)), nil
}

// writeCreationLog inserts a RuleManagementLog entry of type RULE_CREATION.
// Failures are logged as warnings and do not affect the caller's return value.
func (t *DatabaseTools) writeCreationLog(input CreateDraftInput, ruleID int64) {
	var reqID *int64
	if input.BaseRequestID != 0 {
		id := input.BaseRequestID
		reqID = &id
	}

	links := pgtype.FlatArray[string]{}
	if len(input.Links) > 0 {
		links = pgtype.FlatArray[string](input.Links)
	} else if input.App != nil && len(input.App.Links) > 0 {
		links = pgtype.FlatArray[string](input.App.Links)
	}

	entry := models.RuleManagementLog{
		Type:         constants.RuleManagementLogTypeCreation,
		RuleID:       ruleID,
		RequestID:    reqID,
		Description:  input.Description,
		RelatedLinks: links,
	}
	if _, err := t.db.Insert(&entry); err != nil {
		slog.Warn("create_draft: failed to write rule management log",
			slog.Int64("rule_id", ruleID),
			slog.String("error", err.Error()))
	}
}

// GetRuleByIDTool fetches a content rule by its ID and returns it as JSON.
func (t *DatabaseTools) GetRuleByIDTool(_ context.Context, args string) (string, error) {
	var params struct {
		RuleID int64 `json:"rule_id"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing get_rule_by_id args: %w", err)
	}
	slog.Info("tool: get_rule_by_id", slog.Int64("rule_id", params.RuleID))
	rule, err := t.db.GetContentRuleByID(params.RuleID)
	if err != nil {
		if errors.Is(err, ksql.ErrRecordNotFound) {
			slog.Error("tool error: rule not found", slog.String("tool_name", "get_rule_by_id"), slog.Int64("rule_id", params.RuleID), slog.String("error", err.Error()))
			return GetJSONErrorMessage("Rule not found in database", nil), nil
		}
		slog.Error("tool error", slog.String("tool_name", "get_rule_by_id"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Rule database lookup error", nil), fmt.Errorf("fetching rule %d: %w", params.RuleID, err)
	}

	out, err := json.Marshal(rule)
	if err != nil {
		return GetJSONErrorMessage("Internal error: failed to turn database rule to JSON", nil), fmt.Errorf("marshaling rule: %w", err)
	}
	return GetJSONSuccessMessage("here is the rule", string(out)), nil
}

// UpdateRuleTool updates editable fields of an existing content rule. Only the
// fields present in the JSON payload are changed; omitted fields are left as-is.
func (t *DatabaseTools) UpdateRuleTool(_ context.Context, args string) (string, error) {
	var params struct {
		RuleID         int64   `json:"rule_id"`
		URI            *string `json:"uri"`
		URIMatching    *string `json:"uri_matching"`
		Body           *string `json:"body"`
		BodyMatching   *string `json:"body_matching"`
		Method         *string `json:"method"`
		RequestPurpose *string `json:"request_purpose"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing update_rule args: %w", err)
	}
	slog.Info("tool: update_rule", slog.Int64("rule_id", params.RuleID))
	rule, err := t.db.GetContentRuleByID(params.RuleID)

	if err != nil {
		if errors.Is(err, ksql.ErrRecordNotFound) {
			slog.Error("tool error: rule not found", slog.String("tool_name", "update_rule"), slog.Int64("rule_id", params.RuleID), slog.String("error", err.Error()))
			return GetJSONErrorMessage("Rule not found", nil), nil
		}

		slog.Error("tool error", slog.String("tool_name", "update_rule"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Rule database level lookup error", nil), fmt.Errorf("fetching rule %d: %w", params.RuleID, err)
	}

	if params.URI != nil {
		rule.Uri = *params.URI
	}
	if params.URIMatching != nil {
		rule.UriMatching = *params.URIMatching
	}
	if params.Body != nil {
		rule.Body = *params.Body
	}
	if params.BodyMatching != nil {
		rule.BodyMatching = *params.BodyMatching
	}
	if params.Method != nil {
		rule.Method = *params.Method
	}
	if params.RequestPurpose != nil {
		rule.RequestPurpose = *params.RequestPurpose
	}
	if t.dryRun {
		slog.Info("dry-run: would update rule", slog.Int64("rule_id", rule.ID))
		return GetJSONSuccessMessage(fmt.Sprintf("dry-run: rule %d would be updated", rule.ID), nil), nil
	}
	if err := t.db.Update(&rule); err != nil {
		slog.Error("tool error", slog.String("tool_name", "update_rule"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Rule database level update error", nil), fmt.Errorf("updating rule %d: %w", params.RuleID, err)
	}
	return GetJSONSuccessMessage(fmt.Sprintf("rule %d updated successfully", rule.ID), nil), nil
}

// GetContentByIDTool fetches a content entry by its ID and returns it as JSON.
func (t *DatabaseTools) GetContentByIDTool(_ context.Context, args string) (string, error) {
	var params struct {
		ContentID int64 `json:"content_id"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing get_content_by_id args: %w", err)
	}
	slog.Info("tool: get_content_by_id", slog.Int64("content_id", params.ContentID))
	content, err := t.db.GetContentByID(params.ContentID)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "get_content_by_id"), slog.String("error", err.Error()))
		if errors.Is(err, ksql.ErrRecordNotFound) {
			return GetJSONErrorMessage("Content not found in database", nil), nil
		}
		return GetJSONErrorMessage("Content database level lookup error", nil), fmt.Errorf("fetching content %d: %w", params.ContentID, err)
	}
	out, err := json.Marshal(content)
	if err != nil {
		return GetJSONErrorMessage("Failed to marshal content from database to JSON", nil), fmt.Errorf("marshaling content: %w", err)
	}
	return GetJSONSuccessMessage("Content found in database", string(out)), nil
}

// UpdateContentTool updates editable fields of an existing content entry. Only
// the fields present in the JSON payload are changed; omitted fields are left as-is.
func (t *DatabaseTools) UpdateContentTool(_ context.Context, args string) (string, error) {
	var params struct {
		ContentID      int64   `json:"content_id"`
		Data           *string `json:"data"`
		Name           *string `json:"name"`
		Description    *string `json:"description"`
		ContentType    *string `json:"content_type"`
		Server         *string `json:"server"`
		StatusCode     *string `json:"status_code"`
		RuleID         int64   `json:"rule_id,omitempty"`
		LogDescription string  `json:"log_description,omitempty"`
	}
	if err := json.Unmarshal([]byte(args), &params); err != nil {
		return GetJSONErrorMessage("Failed to parse args", nil), fmt.Errorf("parsing update_content args: %w", err)
	}
	slog.Info("tool: update_content", slog.Int64("content_id", params.ContentID))
	content, err := t.db.GetContentByID(params.ContentID)
	if err != nil {
		slog.Error("tool error", slog.String("tool_name", "update_content"), slog.String("error", err.Error()))
		if errors.Is(err, ksql.ErrRecordNotFound) {
			return GetJSONErrorMessage("Content with this ID was not found in the database", nil), nil
		}

		return GetJSONErrorMessage("Content database level lookup error", nil), fmt.Errorf("fetching content %d: %w", params.ContentID, err)
	}
	if params.Data != nil {
		content.Data = models.YammableBytes(*params.Data)
	}
	if params.Name != nil {
		content.Name = *params.Name
	}
	if params.Description != nil {
		content.Description = *params.Description
	}
	if params.ContentType != nil {
		content.ContentType = *params.ContentType
	}
	if params.Server != nil {
		content.Server = *params.Server
	}
	if params.StatusCode != nil {
		content.StatusCode = *params.StatusCode
	}
	if t.dryRun {
		slog.Info("dry-run mode: would have updated the content", slog.Int64("content_id", content.ID))
		return GetJSONSuccessMessage(fmt.Sprintf("dry-run: content %d would be updated", content.ID), nil), nil
	}
	if err := t.db.Update(&content); err != nil {
		slog.Error("tool error", slog.String("tool_name", "update_content"), slog.String("error", err.Error()))
		return GetJSONErrorMessage("Content database level update error", nil), fmt.Errorf("updating content %d: %w", params.ContentID, err)
	}

	if params.RuleID != 0 {
		entry := models.RuleManagementLog{
			Type:         constants.RuleManagementLogTypeUpdateContent,
			RuleID:       params.RuleID,
			Description:  params.LogDescription,
			RelatedLinks: pgtype.FlatArray[string]{},
		}
		if _, err := t.db.Insert(&entry); err != nil {
			slog.Warn("update_content: failed to write rule management log",
				slog.Int64("content_id", params.ContentID),
				slog.Int64("rule_id", params.RuleID),
				slog.String("error", err.Error()))
		}
	}

	return GetJSONSuccessMessage(fmt.Sprintf("content %d updated successfully", content.ID), nil), nil
}

func (t *DatabaseTools) resolveOrCreateApp(input CreateDraftInput) (int64, error) {
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

	source := constants.SourceTypeRuleAgent
	app := models.Application{
		ExtUuid: uuid.NewString(),
		Name:    input.App.Name,
		Version: &version,
		Vendor:  &vendor,
		CVES:    cves,
		Links:   links,
		IsDraft: true,
		Source:  &source,
	}

	dm, err := t.db.Insert(&app)
	if err != nil {
		return 0, fmt.Errorf("inserting app: %w", err)
	}
	return dm.ModelID(), nil
}

func (t *DatabaseTools) createContent(c DraftContent) (int64, error) {
	headers := pgtype.FlatArray[string](c.Headers)

	source := constants.SourceTypeRuleAgent
	content := models.Content{
		Name:        c.Name,
		Description: c.Description,
		Data:        models.YammableBytes(c.Data),
		ContentType: c.ContentType,
		Server:      c.Server,
		StatusCode:  c.StatusCode,
		Headers:     headers,
		ExtUuid:     uuid.NewString(),
		IsDraft:     true,
		Source:      &source,
	}

	dm, err := t.db.Insert(&content)
	if err != nil {
		return 0, fmt.Errorf("inserting content: %w", err)
	}
	return dm.ModelID(), nil
}

func (t *DatabaseTools) createRule(r DraftRule, appID, contentID int64) (int64, error) {
	validPurposes := map[string]bool{
		constants.KillChainPhaseUnknown:      true,
		constants.KillChainPhaseRecon:        true,
		constants.KillChainPhaseVerify:       true,
		constants.KillChainPhaseExploitation: true,
		constants.KillChainPhaseCleanup:      true,
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
			slog.String("got", uriMatching))
		uriMatching = constants.MatchingTypeNone
	}

	bodyMatching := r.BodyMatching
	if r.Body == "" {
		bodyMatching = constants.MatchingTypeNone
	} else if !validMatchingTypes[bodyMatching] {
		slog.Warn("createRule: invalid body_matching, defaulting to none",
			slog.String("got", bodyMatching))
		bodyMatching = constants.MatchingTypeNone
	}

	requestPurpose := r.RequestPurpose
	if !validPurposes[requestPurpose] {
		slog.Warn("createRule: invalid request_purpose, defaulting to UNKNOWN",
			slog.String("got", requestPurpose))
		requestPurpose = constants.RuleRequestPurposeUnknown
	}

	source := constants.SourceTypeRuleAgent
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
		ExtUuid:          uuid.NewString(),
		ContentID:        contentID,
		Enabled:          false,
		IsDraft:          true,
		MonitorKillchain: true,
		Source:           &source,
		LastEvaluatedAt:  time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	dm, err := t.db.Insert(&rule)
	if err != nil {
		return 0, fmt.Errorf("inserting rule: %w", err)
	}
	return dm.ModelID(), nil
}
