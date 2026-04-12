// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
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
package database

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"time"

	"lophiid/pkg/database/models"
	"lophiid/pkg/util"

	"github.com/google/uuid"
	"github.com/vingarcia/ksql"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")
var AppTable = ksql.NewTable("app")
var RequestMetadataTable = ksql.NewTable("request_metadata")
var DownloadTable = ksql.NewTable("downloads")
var HoneypotTable = ksql.NewTable("honeypot")
var WhoisTable = ksql.NewTable("whois")
var StoredQueryTable = ksql.NewTable("stored_query")
var TagTable = ksql.NewTable("tag")
var TagPerRequestTable = ksql.NewTable("tag_per_request")
var TagPerQueryTable = ksql.NewTable("tag_per_query")
var P0fResultTable = ksql.NewTable("p0f_result")
var IpEventTable = ksql.NewTable("ip_event")
var SessionTable = ksql.NewTable("session")
var RequestDescriptionTable = ksql.NewTable("request_description")
var SessionContextTable = ksql.NewTable("session_execution_context")
var YaraTable = ksql.NewTable("yara")
var CodeEmuTable = ksql.NewTable("llm_code_execution")
var TagPerRuleTable = ksql.NewTable("tag_per_rule")
var AppPerGroupTable = ksql.NewTable("app_per_group")
var RuleGroupTable = ksql.NewTable("rule_group")
var CampaignTable = ksql.NewTable("campaign")
var CampaignRequestTable = ksql.NewTable("campaign_request")
var KillChainTable = ksql.NewTable("kill_chain")
var SingleKillChainPhaseTable = ksql.NewTable("single_kill_chain_phase")

type DatabaseClient interface {
	Close()
	Insert(dm models.DataModel) (models.DataModel, error)
	InsertBatch(dms []models.DataModel) error
	InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error)

	Update(dm models.DataModel) error
	Delete(dm models.DataModel) error

	GetAppByID(id int64) (models.Application, error)
	SearchApps(offset int64, limit int64, query string) ([]models.Application, error)
	GetContentByID(id int64) (models.Content, error)
	GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error)
	SearchP0fResult(offset int64, limit int64, query string) ([]models.P0fResult, error)
	GetRequestByID(id int64) (models.Request, error)
	SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error)
	SearchRequests(offset int64, limit int64, query string) ([]models.Request, error)
	SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error)
	GetContentRuleByID(id int64) (models.ContentRule, error)
	SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error)
	SearchContent(offset int64, limit int64, query string) ([]models.Content, error)
	SearchYara(offset int64, limit int64, query string) ([]models.Yara, error)
	SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error)
	SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error)
	SearchSession(offset int64, limit int64, query string) ([]models.Session, error)
	SearchRequestDescription(offset int64, limit int64, query string) ([]models.RequestDescription, error)
	SearchSessionExecutionContext(offset int64, limit int64, query string) ([]models.SessionExecutionContext, error)
	CampaignGetUnassignedRequestsWithDescriptions(isMalicious bool, startTime, endTime time.Time) ([]models.RequestWithDescription, error)
	GetUnassignedRequestsForCampaignSessions(campaignID int64, startTime, endTime, campaignStart, campaignEnd time.Time) ([]models.Request, error)
	SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error)
	SearchTags(offset int64, limit int64, query string) ([]models.Tag, error)
	SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error)
	SearchTagPerRule(offset int64, limit int64, query string) ([]models.TagPerRule, error)
	SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error)
	SearchAppPerGroup(offset int64, limit int64, query string) ([]models.AppPerGroup, error)
	SearchRuleGroup(offset int64, limit int64, query string) ([]models.RuleGroup, error)
	SearchCampaigns(offset int64, limit int64, query string) ([]models.Campaign, error)
	SearchCampaignRequests(offset int64, limit int64, query string) ([]models.CampaignRequest, error)
	GetCampaignByID(id int64) (models.Campaign, error)
	SearchKillChains(offset int64, limit int64, query string) ([]models.KillChain, error)
	SearchSingleKillChainPhases(offset int64, limit int64, query string) ([]models.SingleKillChainPhase, error)
	GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error)
	GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error)
	GetAppPerGroupJoin() ([]models.AppPerGroupJoin, error)
	ReplaceAppsForGroup(groupID int64, appIDs []int64) error
	GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error)
	BulkGetByField(tableName string, field string, values any, dest any) error
	SimpleQuery(query string, result any) (any, error)
	ParameterizedQuery(query string, result any, params ...any) (any, error)
	ExecStatement(query string, params ...any) error
}

// Helper function to get database field names.
func getDatamodelDatabaseFields(datamodel any) []string {
	var ret []string

	val := reflect.TypeOf(datamodel)
	// If it's an interface or a pointer, unwrap it.
	if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}

	for i := range val.NumField() {
		tvalue := val.Field(i).Tag.Get("ksql")
		if tvalue != "" {
			idx := strings.Index(tvalue, ",")
			if idx != -1 {
				tvalue = tvalue[:idx]
			}
			ret = append(ret, tvalue)
		}
	}
	return ret
}

type FieldDocEntry struct {
	FieldType string `json:"field_type"`
	FieldDoc  string `json:"field_doc"`
}

// GetDatamodelDocumentationMap returns a map with the field name as key and
// field documentation as value.
func GetDatamodelDocumentationMap(datamodel any) map[string]FieldDocEntry {
	ret := make(map[string]FieldDocEntry)
	t := reflect.TypeOf(datamodel)
	for i := range t.NumField() {
		docValue := t.Field(i).Tag.Get("doc")
		fieldValue := t.Field(i).Tag.Get("ksql")
		if docValue != "" && fieldValue != "" {
			idx := strings.Index(fieldValue, ",")
			if idx != -1 {
				fieldValue = fieldValue[:idx]
			}

			fieldType := ""
			if t.Field(i).Type.Name() != "" {
				fieldType = t.Field(i).Type.Name()
			}

			ret[fieldValue] = FieldDocEntry{
				FieldType: fieldType,
				FieldDoc:  docValue,
			}
		}
	}
	return ret
}

type KSQLClient struct {
	db  *ksql.DB
	ctx context.Context
}

func NewKSQLClient(db *ksql.DB) *KSQLClient {
	return &KSQLClient{
		db:  db,
		ctx: context.Background(),
	}
}

func (d *KSQLClient) Close() {
	if d.db == nil {
		fmt.Printf("Cannot close closed db")
		return
	}
	d.db.Close()
}

func (d *KSQLClient) getTableForModel(dm models.DataModel) *ksql.Table {
	name := util.GetStructName(dm)

	sqlTable := make(map[string]*ksql.Table)
	sqlTable["Application"] = &AppTable
	sqlTable["Request"] = &RequestTable
	sqlTable["Content"] = &ContentTable
	sqlTable["ContentRule"] = &ContentRuleTable
	sqlTable["RequestMetadata"] = &RequestMetadataTable
	sqlTable["Download"] = &DownloadTable
	sqlTable["Honeypot"] = &HoneypotTable
	sqlTable["Whois"] = &WhoisTable
	sqlTable["StoredQuery"] = &StoredQueryTable
	sqlTable["Tag"] = &TagTable
	sqlTable["TagPerQuery"] = &TagPerQueryTable
	sqlTable["TagPerRequest"] = &TagPerRequestTable
	sqlTable["P0fResult"] = &P0fResultTable
	sqlTable["IpEvent"] = &IpEventTable
	sqlTable["Session"] = &SessionTable
	sqlTable["RequestDescription"] = &RequestDescriptionTable
	sqlTable["Yara"] = &YaraTable
	sqlTable["SessionExecutionContext"] = &SessionContextTable
	sqlTable["LLMCodeExecution"] = &CodeEmuTable
	sqlTable["TagPerRule"] = &TagPerRuleTable
	sqlTable["AppPerGroup"] = &AppPerGroupTable
	sqlTable["RuleGroup"] = &RuleGroupTable
	sqlTable["Campaign"] = &CampaignTable
	sqlTable["CampaignRequest"] = &CampaignRequestTable
	sqlTable["KillChain"] = &KillChainTable
	sqlTable["SingleKillChainPhase"] = &SingleKillChainPhaseTable

	table, ok := sqlTable[name]
	if !ok {
		slog.Error("Don't know datamodel!!", slog.String("datamodel", name))
		return nil
	}

	return table
}

// getTableNameForModel returns the SQL table name string for a DataModel.
func (d *KSQLClient) getTableNameForModel(dm models.DataModel) string {
	name := util.GetStructName(dm)
	tableNames := map[string]string{
		"Application":             "app",
		"Request":                 "request",
		"Content":                 "content",
		"ContentRule":             "content_rule",
		"RequestMetadata":         "request_metadata",
		"Download":                "downloads",
		"Honeypot":                "honeypot",
		"Whois":                   "whois",
		"StoredQuery":             "stored_query",
		"Tag":                     "tag",
		"TagPerQuery":             "tag_per_query",
		"TagPerRequest":           "tag_per_request",
		"P0fResult":               "p0f_result",
		"IpEvent":                 "ip_event",
		"Session":                 "session",
		"RequestDescription":      "request_description",
		"Yara":                    "yara",
		"SessionExecutionContext": "session_execution_context",
		"LLMCodeExecution":        "llm_code_execution",
		"TagPerRule":              "tag_per_rule",
		"AppPerGroup":             "app_per_group",
		"RuleGroup":               "rule_group",
		"Campaign":                "campaign",
		"CampaignRequest":         "campaign_request",
		"SingleKillChainPhase":    "single_kill_chain_phase",
	}
	if tn, ok := tableNames[name]; ok {
		return tn
	}
	return ""
}

// insertFieldInfo holds metadata for a single struct field used in batch inserts.
type insertFieldInfo struct {
	columnName string
	fieldIndex int
	timeNowUTC bool
}

// parseInsertFields extracts column names and field indices from a DataModel
// type, skipping fields tagged with skipInserts.
func parseInsertFields(dm models.DataModel) []insertFieldInfo {
	val := reflect.TypeOf(dm)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	var fields []insertFieldInfo
	for i := range val.NumField() {
		tag := val.Field(i).Tag.Get("ksql")
		if tag == "" {
			continue
		}
		parts := strings.Split(tag, ",")
		colName := parts[0]
		skip := false
		timeNow := false
		for _, p := range parts[1:] {
			switch p {
			case "skipInserts":
				skip = true
			case "timeNowUTC":
				timeNow = true
			case "skipUpdates":
				// Known modifier, not relevant for inserts.
			default:
				slog.Error("unknown ksql tag modifier",
					slog.String("modifier", p),
					slog.String("field", val.Field(i).Name),
				)
			}
		}
		if skip {
			continue
		}
		fields = append(fields, insertFieldInfo{
			columnName: colName,
			fieldIndex: i,
			timeNowUTC: timeNow,
		})
	}
	return fields
}

// BuildBatchInsertQuery constructs a parameterized INSERT statement and its
// corresponding parameter slice for a batch of DataModel rows. The tableName
// identifies the target table and all models must be of the same concrete type.
func BuildBatchInsertQuery(tableName string, dms []models.DataModel) (string, []any, error) {
	if len(dms) == 0 {
		return "", nil, fmt.Errorf("empty model slice")
	}

	fields := parseInsertFields(dms[0])
	if len(fields) == 0 {
		return "", nil, fmt.Errorf("no insertable fields for model")
	}

	// Build column list.
	cols := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = f.columnName
	}

	// Build VALUES placeholders and collect params.
	now := time.Now().UTC()
	colCount := len(fields)
	params := make([]any, 0, colCount*len(dms))
	valueClauses := make([]string, 0, len(dms))

	for rowIdx, dm := range dms {
		placeholders := make([]string, colCount)
		rv := reflect.ValueOf(dm)
		if rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}
		for colIdx, f := range fields {
			paramIdx := rowIdx*colCount + colIdx + 1
			placeholders[colIdx] = fmt.Sprintf("$%d", paramIdx)
			if f.timeNowUTC {
				params = append(params, now)
			} else {
				params = append(params, rv.Field(f.fieldIndex).Interface())
			}
		}
		valueClauses = append(valueClauses, "("+strings.Join(placeholders, ", ")+")")
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s",
		tableName,
		strings.Join(cols, ", "),
		strings.Join(valueClauses, ", "),
	)

	return query, params, nil
}

// InsertBatch inserts multiple DataModel rows in a single INSERT statement.
// All models in the slice must be of the same concrete type.
func (d *KSQLClient) InsertBatch(dms []models.DataModel) error {
	if len(dms) == 0 {
		return nil
	}

	tableName := d.getTableNameForModel(dms[0])
	if tableName == "" {
		return fmt.Errorf("unknown datamodel: %v", dms[0])
	}

	query, params, err := BuildBatchInsertQuery(tableName, dms)
	if err != nil {
		return fmt.Errorf("building batch insert query: %w", err)
	}

	_, err = d.db.Exec(d.ctx, query, params...)
	return err
}

func (d *KSQLClient) Insert(dm models.DataModel) (models.DataModel, error) {
	t := d.getTableForModel(dm)
	if t == nil {
		return dm, fmt.Errorf("unknown datamodel: %v", dm)
	}
	err := d.db.Insert(d.ctx, *t, dm)
	return dm, err
}

// InsertExternalModel inserts the model in the database and makes sure the uuid
// field is actually set.
func (d *KSQLClient) InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error) {
	t := d.getTableForModel(dm)
	if t == nil {
		return dm, fmt.Errorf("unknown datamodel: %v", dm)
	}

	if dm.ExternalUuid() == "" {
		dm.SetExternalUuid(uuid.NewString())
	}
	err := d.db.Insert(d.ctx, *t, dm)
	return dm, err
}

func (d *KSQLClient) Update(dm models.DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("unknown datamodel: %v", dm)
	}
	return d.db.Patch(d.ctx, *t, dm)
}

func (d *KSQLClient) Delete(dm models.DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("unknown datamodel: %v", dm)
	}
	return d.db.Delete(d.ctx, *t, dm.ModelID())
}

func (d *KSQLClient) GetAppByID(id int64) (models.Application, error) {
	ap := models.Application{}
	err := d.db.QueryOne(d.ctx, &ap, fmt.Sprintf("FROM app WHERE id = %d", id))
	if ap.ID == 0 {
		return ap, fmt.Errorf("found no app for ID: %d", id)
	}
	return ap, err
}

func (d *KSQLClient) GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error) {
	hp := models.P0fResult{}
	err := d.db.QueryOne(d.ctx, &hp, fmt.Sprintf("FROM p0f_result WHERE ip = $1 %s", querySuffix), ip)
	return hp, err
}

func (d *KSQLClient) SearchP0fResult(offset int64, limit int64, query string) ([]models.P0fResult, error) {
	var result []models.P0fResult
	err := d.Search(offset, limit, query, p0fResultConfig, &result)
	return result, err
}

func (d *KSQLClient) GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error) {
	var tags []models.TagPerRequest
	err := d.db.Query(d.ctx, &tags, "FROM tag_per_request WHERE request_id = $1", id)
	return tags, err
}

func (d *KSQLClient) GetRequestByID(id int64) (models.Request, error) {
	var rs models.Request
	err := d.db.QueryOne(d.ctx, &rs, "FROM request WHERE id = $1", id)
	return rs, err
}

func (d *KSQLClient) SimpleQuery(query string, result any) (any, error) {
	err := d.db.Query(d.ctx, result, query)
	return result, err
}

// ParameterizedQuery executes a SQL query with positional parameters ($1, $2, …).
func (d *KSQLClient) ParameterizedQuery(query string, result any, params ...any) (any, error) {
	err := d.db.Query(d.ctx, result, query, params...)
	return result, err
}

// ExecStatement executes a SQL statement (UPDATE, DELETE, etc.) that does not
// return rows. Use this instead of ParameterizedQuery for bulk mutations.
func (d *KSQLClient) ExecStatement(query string, params ...any) error {
	_, err := d.db.Exec(d.ctx, query, params...)
	return err
}

// Search performs a generic search operation using the provided configuration
func (d *KSQLClient) Search(offset int64, limit int64, query string, config SearchConfig, result any) error {
	params, err := ParseQuery(query, config.AllowedFields)
	if err != nil {
		return fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	queryStart := fmt.Sprintf("FROM %s", config.TableName)

	queryEnd := ""
	if config.OrderBy != "" {
		queryEnd += fmt.Sprintf(" ORDER BY %s", config.OrderBy)
	}
	queryEnd += fmt.Sprintf(" OFFSET %d LIMIT %d", offset, limit)

	query, values, err := buildComposedQuery(params, queryStart, queryEnd)
	if err != nil {
		return fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, result, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return err
}

func (d *KSQLClient) SearchRequests(offset int64, limit int64, query string) ([]models.Request, error) {
	var rs []models.Request

	allowedFields := getDatamodelDatabaseFields(models.Request{})
	allowedFields = append(allowedFields, "label")
	params, err := ParseQuery(query, allowedFields)
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM request", fmt.Sprintf("ORDER BY time_received DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)

	if err != nil {
		return rs, fmt.Errorf("error querying requests: %w", err)
	}

	var ret []models.Request

	uniqueIPs := make(map[string]models.P0fResult)
	uniqueIPsMu := sync.RWMutex{}

	concurrentWorkers := int(limit/10) + 1
	jobs := make(chan models.Request, len(rs))
	results := make(chan models.Request, len(rs))

	for range concurrentWorkers {
		go func() {
			for req := range jobs {
				tags, err := d.GetTagPerRequestFullForRequest(req.ID)
				if err != nil {
					slog.Warn("error getting tags for request", slog.String("error", err.Error()))
					req.Tags = []models.TagPerRequestFull{}
				} else {
					req.Tags = append(req.Tags, tags...)
				}

				uniqueIPsMu.RLock()
				pr, ok := uniqueIPs[req.SourceIP]
				uniqueIPsMu.RUnlock()

				if !ok {
					pr, err = d.GetP0fResultByIP(req.SourceIP, "ORDER BY last_seen_time DESC LIMIT 1")
					if err == nil {
						uniqueIPsMu.Lock()
						uniqueIPs[req.SourceIP] = pr
						uniqueIPsMu.Unlock()
					} else {
						pr = models.P0fResult{}
					}
				}
				req.P0fResult = pr
				results <- req
			}
		}()
	}

	for _, req := range rs {
		jobs <- req
		req := <-results
		ret = append(ret, req)
	}

	close(jobs)
	close(results)

	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return ret, err
}

func (d *KSQLClient) SearchContent(offset int64, limit int64, query string) ([]models.Content, error) {
	var result []models.Content
	err := d.Search(offset, limit, query, contentConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchSessionExecutionContext(offset int64, limit int64, query string) ([]models.SessionExecutionContext, error) {
	var result []models.SessionExecutionContext
	err := d.Search(offset, limit, query, sessionContextConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchYara(offset int64, limit int64, query string) ([]models.Yara, error) {
	var result []models.Yara
	err := d.Search(offset, limit, query, yaraConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error) {
	var result []models.ContentRule
	err := d.Search(offset, limit, query, contentRulesConfig, &result)

	// Post-process stored query results to add tags
	for i := range result {
		tags, err := d.SearchTagPerRule(0, 200, fmt.Sprintf("rule_id:%d", result[i].ID))
		if err != nil {
			return result, fmt.Errorf("cannot get tags for rule: %s", err.Error())
		}
		result[i].TagsToApply = append(result[i].TagsToApply, tags...)
	}
	return result, err
}

func (d *KSQLClient) SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error) {
	var result []models.IpEvent
	err := d.Search(offset, limit, query, eventsConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchSession(offset int64, limit int64, query string) ([]models.Session, error) {
	var result []models.Session
	err := d.Search(offset, limit, query, sessionConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchRequestDescription(offset int64, limit int64, query string) ([]models.RequestDescription, error) {
	var result []models.RequestDescription
	err := d.Search(offset, limit, query, requestDescriptionConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchApps(offset int64, limit int64, query string) ([]models.Application, error) {
	var result []models.Application
	err := d.Search(offset, limit, query, appsConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error) {
	var result []models.Download
	err := d.Search(offset, limit, query, downloadsConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error) {
	var result []models.Honeypot
	err := d.Search(offset, limit, query, honeypotConfig, &result)
	if err != nil {
		return result, err
	}

	// Post-process honeypot results to add request counts
	type Count struct {
		Count int64 `ksql:"cnt"`
	}
	for i := range result {
		var cnt Count
		err = d.db.QueryOne(d.ctx, &cnt,
			"SELECT COUNT(*) as cnt FROM request WHERE honeypot_ip = $1 AND time_received >= date_trunc('day', current_date - interval '1'day);",
			result[i].IP)
		if err != nil {
			return result, fmt.Errorf("error fetching count: %w", err)
		}
		result[i].RequestsCountLastDay = cnt.Count
	}
	return result, nil
}

func (d *KSQLClient) SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error) {
	var result []models.StoredQuery
	err := d.Search(offset, limit, query, storedQueryConfig, &result)
	if err != nil {
		return result, err
	}

	// Post-process stored query results to add tags
	for i := range result {
		tags, err := d.SearchTagPerQuery(0, 100, fmt.Sprintf("query_id:%d", result[i].ID))
		if err != nil {
			return result, fmt.Errorf("cannot get tags for query: %s", err.Error())
		}
		result[i].TagsToApply = append(result[i].TagsToApply, tags...)
	}
	return result, nil
}

func (d *KSQLClient) SearchTags(offset int64, limit int64, query string) ([]models.Tag, error) {
	var result []models.Tag
	err := d.Search(offset, limit, query, tagsConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error) {
	var result []models.Whois
	err := d.Search(offset, limit, query, whoisConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error) {
	var result []models.TagPerQuery
	err := d.Search(offset, limit, query, tagPerQueryConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchTagPerRule(offset int64, limit int64, query string) ([]models.TagPerRule, error) {
	var result []models.TagPerRule
	err := d.Search(offset, limit, query, tagPerRuleConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error) {
	var result []models.TagPerRequest
	err := d.Search(offset, limit, query, tagPerRequestConfig, &result)
	return result, err
}

func (d *KSQLClient) SearchAppPerGroup(offset int64, limit int64, query string) ([]models.AppPerGroup, error) {
	var result []models.AppPerGroup
	err := d.Search(offset, limit, query, appPerGroupConfig, &result)
	return result, err
}

// SearchRuleGroup searches for rule groups based on the query.
func (d *KSQLClient) SearchRuleGroup(offset int64, limit int64, query string) ([]models.RuleGroup, error) {
	var result []models.RuleGroup
	err := d.Search(offset, limit, query, ruleGroupConfig, &result)
	return result, err
}

func (d *KSQLClient) CampaignGetUnassignedRequestsWithDescriptions(isMalicious bool, startTime, endTime time.Time) ([]models.RequestWithDescription, error) {
	var rds []models.RequestWithDescription
	var err error
	if isMalicious {
		err = d.db.Query(d.ctx, &rds, "FROM request JOIN request_description ON request.cmp_hash = request_description.cmp_hash AND request.campaign_id IS NULL AND ai_malicious = 'yes' AND request.time_received BETWEEN $1 AND $2", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	} else {
		err = d.db.Query(d.ctx, &rds, "FROM request JOIN request_description ON request.cmp_hash = request_description.cmp_hash AND request.campaign_id IS NULL AND ai_malicious != 'yes' AND request.time_received BETWEEN $1 AND $2", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	}
	return rds, err
}

// GetUnassignedRequestsForCampaignSessions returns all unassigned requests
// whose session_id appears in any request already belonging to the given
// campaign, restricted to the given time window. The time window should be
// padded around the campaign's first/last seen timestamps.
func (d *KSQLClient) GetUnassignedRequestsForCampaignSessions(campaignID int64, startTime, endTime, campaignStart, campaignEnd time.Time) ([]models.Request, error) {
	var result []models.Request
	err := d.db.Query(d.ctx, &result,
		"FROM request WHERE campaign_id IS NULL AND session_id != 0 AND time_received BETWEEN $2 AND $3 AND session_id IN (SELECT DISTINCT session_id FROM request WHERE campaign_id = $1 AND session_id != 0 AND time_received BETWEEN $4 AND $5)",
		campaignID, startTime.Format(time.RFC3339), endTime.Format(time.RFC3339), campaignStart.Format(time.RFC3339), campaignEnd.Format(time.RFC3339),
	)
	return result, err
}

func (d *KSQLClient) GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error) {
	var md []models.TagPerRequestFull
	err := d.db.Query(d.ctx, &md, "FROM tag_per_request JOIN tag ON tag.id = tag_per_request.tag_id AND tag_per_request.request_id = $1", id)
	return md, err
}

func (d *KSQLClient) GetAppPerGroupJoin() ([]models.AppPerGroupJoin, error) {
	var md []models.AppPerGroupJoin
	err := d.db.Query(d.ctx, &md, "FROM app_per_group JOIN app ON app.id = app_per_group.app_id JOIN rule_group ON app_per_group.group_id = rule_group.id")
	return md, err
}

// ReplaceAppsForGroup atomically replaces all app_per_group entries for the
// given group ID within a single transaction.
func (d *KSQLClient) ReplaceAppsForGroup(groupID int64, appIDs []int64) error {
	return d.db.Transaction(d.ctx, func(db ksql.Provider) error {
		if _, err := db.Exec(d.ctx, "DELETE FROM app_per_group WHERE group_id = $1", groupID); err != nil {
			return fmt.Errorf("deleting existing apps: %w", err)
		}

		for _, appID := range appIDs {
			apg := models.AppPerGroup{
				AppID:   appID,
				GroupID: groupID,
			}
			if err := db.Insert(d.ctx, AppPerGroupTable, &apg); err != nil {
				return fmt.Errorf("inserting app %d: %w", appID, err)
			}
		}

		return nil
	})
}

// SearchCampaigns searches for campaigns based on the query.
func (d *KSQLClient) SearchCampaigns(offset int64, limit int64, query string) ([]models.Campaign, error) {
	var result []models.Campaign
	err := d.Search(offset, limit, query, campaignConfig, &result)
	return result, err
}

// SearchCampaignRequests searches for campaign request links based on the query.
func (d *KSQLClient) SearchCampaignRequests(offset int64, limit int64, query string) ([]models.CampaignRequest, error) {
	var result []models.CampaignRequest
	err := d.Search(offset, limit, query, campaignRequestConfig, &result)
	return result, err
}

// SearchKillChains searches for kill chain records.
func (d *KSQLClient) SearchKillChains(offset int64, limit int64, query string) ([]models.KillChain, error) {
	var result []models.KillChain
	err := d.Search(offset, limit, query, killChainConfig, &result)
	return result, err
}

// SearchSingleKillChainPhases searches for single kill chain phase records.
func (d *KSQLClient) SearchSingleKillChainPhases(offset int64, limit int64, query string) ([]models.SingleKillChainPhase, error) {
	var result []models.SingleKillChainPhase
	err := d.Search(offset, limit, query, singleKillChainPhaseConfig, &result)
	return result, err
}

// GetCampaignByID returns a single campaign by its ID.
func (d *KSQLClient) GetCampaignByID(id int64) (models.Campaign, error) {
	var c models.Campaign
	err := d.db.QueryOne(d.ctx, &c, "FROM campaign WHERE id = $1", id)
	return c, err
}

// bulkFetchableEntry pairs a SQL table name with its Go model for reflection.
type bulkFetchableEntry struct {
	tableName string
	model     any
}

// bulkFetchableModels is the explicit list of models that may be bulk-fetched.
// Adding a model here automatically permits all of its ksql-tagged columns.
var bulkFetchableModels = []bulkFetchableEntry{
	{"request", models.Request{}},
	{"request_description", models.RequestDescription{}},
	{"p0f_result", models.P0fResult{}},
	{"whois", models.Whois{}},
}

// bulkFetchAllowlist maps table name → allowed field names, built at init time.
var bulkFetchAllowlist map[string]map[string]bool

func init() {
	bulkFetchAllowlist = make(map[string]map[string]bool, len(bulkFetchableModels))
	for _, entry := range bulkFetchableModels {
		fields := getDatamodelDatabaseFields(entry.model)
		allowed := make(map[string]bool, len(fields))
		for _, f := range fields {
			allowed[f] = true
		}
		bulkFetchAllowlist[entry.tableName] = allowed
	}
}

// bulkGetChunkSize is the maximum number of values per BulkGetByField query.
const bulkGetChunkSize = 5000

// BulkGetByField fetches all rows from tableName where field matches any value
// in values (a slice), scanning results into dest (a pointer to a slice). Both
// tableName and field are validated against the allowlist before use. When
// len(values) exceeds bulkGetChunkSize the query is split into multiple chunks
// and the results are merged into dest.
func (d *KSQLClient) BulkGetByField(tableName, field string, values any, dest any) error {
	fields, ok := bulkFetchAllowlist[tableName]
	if !ok || !fields[field] {
		return fmt.Errorf("BulkGetByField: disallowed combination: %s.%s", tableName, field)
	}

	// Validate dest: must be a non-nil pointer to a slice.
	dVal := reflect.ValueOf(dest)
	if dVal.Kind() != reflect.Ptr || dVal.IsNil() {
		return fmt.Errorf("BulkGetByField: dest must be a non-nil pointer, got %T", dest)
	}
	if dVal.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("BulkGetByField: dest must be a pointer to a slice, got pointer to %s", dVal.Elem().Kind())
	}

	// Validate values: must be a slice. Wrap a scalar into a 1-element slice so
	// the WHERE field = ANY($1) query always receives an array-like parameter.
	vVal := reflect.ValueOf(values)
	if vVal.Kind() != reflect.Slice {
		wrapped := reflect.MakeSlice(reflect.SliceOf(vVal.Type()), 1, 1)
		wrapped.Index(0).Set(vVal)
		vVal = wrapped
		values = vVal.Interface()
	}

	query := fmt.Sprintf("FROM %s WHERE %s = ANY($1)", tableName, field)

	// For slices within the chunk size, use a single query.
	if vVal.Len() <= bulkGetChunkSize {
		return d.db.Query(d.ctx, dest, query, values)
	}

	// Reset dest before accumulating to avoid appending to stale data when
	// callers reuse the same slice across multiple calls.
	destVal := dVal.Elem()
	destVal.Set(reflect.MakeSlice(destVal.Type(), 0, 0))

	// Split into chunks and accumulate results into dest.
	total := vVal.Len()
	for start := 0; start < total; start += bulkGetChunkSize {
		end := start + bulkGetChunkSize
		if end > total {
			end = total
		}
		chunk := vVal.Slice(start, end).Interface()
		chunkDest := reflect.New(reflect.SliceOf(destVal.Type().Elem()))
		if err := d.db.Query(d.ctx, chunkDest.Interface(), query, chunk); err != nil {
			return err
		}
		destVal.Set(reflect.AppendSlice(destVal, chunkDest.Elem()))
	}
	return nil
}

func (d *KSQLClient) GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error) {
	var md []models.RequestMetadata
	err := d.db.Query(d.ctx, &md, "FROM request_metadata WHERE request_id = $1 ORDER BY type", id)
	return md, err
}

func (d *KSQLClient) GetContentRuleByID(id int64) (models.ContentRule, error) {
	cr := models.ContentRule{}
	err := d.db.QueryOne(d.ctx, &cr, "FROM content_rule WHERE id = $1", id)
	if cr.ID == 0 {
		return cr, fmt.Errorf("found no content rule for ID: %d", id)
	}
	return cr, err
}

func (d *KSQLClient) GetContentByID(id int64) (models.Content, error) {
	ct := models.Content{}
	err := d.db.QueryOne(d.ctx, &ct, "FROM content WHERE id = $1", id)
	// TODO: it should be safe to remove the next condition because QueryOne
	// returns an error ErrRecordNotFound when no records are found.
	if ct.ID == 0 {
		return ct, fmt.Errorf("found no content for ID: %d", id)
	}
	return ct, err
}
