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

type DatabaseClient interface {
	Close()
	Insert(dm models.DataModel) (models.DataModel, error)
	InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error)

	Update(dm models.DataModel) error
	Delete(dm models.DataModel) error

	GetAppByID(id int64) (models.Application, error)
	SearchApps(offset int64, limit int64, query string) ([]models.Application, error)
	GetContentByID(id int64) (models.Content, error)
	GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error)
	GetRequestByID(id int64) (models.Request, error)
	SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error)
	SearchRequests(offset int64, limit int64, query string) ([]models.Request, error)
	SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error)
	SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error)
	SearchContent(offset int64, limit int64, query string) ([]models.Content, error)
	SearchYara(offset int64, limit int64, query string) ([]models.Yara, error)
	SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error)
	SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error)
	SearchSession(offset int64, limit int64, query string) ([]models.Session, error)
	SearchRequestDescription(offset int64, limit int64, query string) ([]models.RequestDescription, error)
	SearchSessionExecutionContext(offset int64, limit int64, query string) ([]models.SessionExecutionContext, error)
	SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error)
	SearchTags(offset int64, limit int64, query string) ([]models.Tag, error)
	SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error)
	SearchTagPerRule(offset int64, limit int64, query string) ([]models.TagPerRule, error)
	SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error)
	GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error)
	GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error)
	GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error)
	SimpleQuery(query string, result any) (any, error)
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

	table, ok := sqlTable[name]
	if !ok {
		slog.Error("Don't know datamodel!!", slog.String("datamodel", name))
		return nil
	}

	return table
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

func (d *KSQLClient) GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error) {
	var md []models.TagPerRequestFull
	err := d.db.Query(d.ctx, &md, "FROM tag_per_request JOIN tag ON tag.id = tag_per_request.tag_id AND tag_per_request.request_id = $1", id)
	return md, err
}

func (d *KSQLClient) GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error) {
	var md []models.RequestMetadata
	err := d.db.Query(d.ctx, &md, "FROM request_metadata WHERE request_id = $1 ORDER BY type", id)
	return md, err
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
