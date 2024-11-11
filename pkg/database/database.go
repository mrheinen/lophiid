// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
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

type DatabaseClient interface {
	Close()
	Insert(dm models.DataModel) (models.DataModel, error)
	InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error)

	Update(dm models.DataModel) error
	Delete(dm models.DataModel) error

	GetAppByID(id int64) (models.Application, error)
	SearchApps(offset int64, limit int64, query string) ([]models.Application, error)
	GetContentByID(id int64) (models.Content, error)
	GetContentRuleByID(id int64) (models.ContentRule, error)
	GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error)
	GetRequestByID(id int64) (models.Request, error)
	SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error)
	SearchRequests(offset int64, limit int64, query string) ([]models.Request, error)
	SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error)
	SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error)
	SearchContent(offset int64, limit int64, query string) ([]models.Content, error)
	SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error)
	SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error)
	SearchSession(offset int64, limit int64, query string) ([]models.Session, error)
	SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error)
	SearchTags(offset int64, limit int64, query string) ([]models.Tag, error)
	SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error)
	SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error)
	GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error)
	GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error)
	GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error)
}

// Helper function to get database field names.
func getDatamodelDatabaseFields(datamodel interface{}) []string {
	var ret []string

	val := reflect.TypeOf(datamodel)
	// If it's an interface or a pointer, unwrap it.
	if val.Kind() == reflect.Ptr && val.Elem().Kind() == reflect.Struct {
		val = val.Elem()
	}

	for i := 0; i < val.NumField(); i++ {
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
func GetDatamodelDocumentationMap(datamodel interface{}) map[string]FieldDocEntry {
	ret := make(map[string]FieldDocEntry)
	t := reflect.TypeOf(datamodel)
	for i := 0; i < t.NumField(); i++ {
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

func (d *KSQLClient) getTableNameForModel(dm models.DataModel) string {
	name := util.GetStructName(dm)
	switch name {
	case "Application":
		return "app"
	case "Content":
		return "content"
	case "ContentRule":
		return "content_rule"
	default:
		slog.Error("Don't know %s datamodel\n", slog.String("name", name))
		return ""
	}
}

func (d *KSQLClient) getTableForModel(dm models.DataModel) *ksql.Table {
	name := util.GetStructName(dm)

	switch name {
	case "models.Application":
		return &AppTable
	case "Request":
		return &RequestTable
	case "Content":
		return &ContentTable
	case "ContentRule":
		return &ContentRuleTable
	case "RequestMetadata":
		return &RequestMetadataTable
	case "Download":
		return &DownloadTable
	case "Honeypot":
		return &HoneypotTable
	case "Whois":
		return &WhoisTable
	case "StoredQuery":
		return &StoredQueryTable
	case "Tag":
		return &TagTable
	case "TagPerQuery":
		return &TagPerQueryTable
	case "TagPerRequest":
		return &TagPerRequestTable
	case "P0fResult":
		return &P0fResultTable
	case "IpEvent":
		return &IpEventTable
	case "Session":
		return &SessionTable

	default:
		fmt.Printf("Don't know %s datamodel\n", name)
		return nil
	}
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
	err := d.db.Query(d.ctx, &rs, "FROM request WHERE id = $1", id)
	return rs, err
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

	for w := 0; w < concurrentWorkers; w++ {
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
	var rs []models.Content

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Content{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM content", fmt.Sprintf("ORDER BY id DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error) {
	var rs []models.ContentRule

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.ContentRule{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM (SELECT * FROM content_rule ", fmt.Sprintf("ORDER BY updated_at DESC OFFSET %d LIMIT %d) AS subq ORDER BY app_id", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error) {
	var rs []models.IpEvent

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.IpEvent{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM ip_event", fmt.Sprintf("ORDER BY id DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchSession(offset int64, limit int64, query string) ([]models.Session, error) {
	var rs []models.Session
	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Session{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM session", fmt.Sprintf("ORDER BY started_at DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchApps(offset int64, limit int64, query string) ([]models.Application, error) {
	var rs []models.Application

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Application{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM app", fmt.Sprintf("ORDER BY updated_at DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error) {
	var rs []models.Download

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Download{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	// Important: the order by last seen is something that the Virustotal manager
	// depends on to return the newest entry.
	query, values, err := buildComposedQuery(params, "FROM downloads", fmt.Sprintf("ORDER BY last_seen_at DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error) {
	var rs []models.Honeypot

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Honeypot{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM honeypot", fmt.Sprintf("ORDER BY last_checkin DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)

	var ret []models.Honeypot
	type Count struct {
		Count int64 `ksql:"cnt"`
	}
	for _, h := range rs {
		var cnt Count
		err = d.db.QueryOne(d.ctx, &cnt, "SELECT COUNT(*) as cnt FROM request WHERE honeypot_ip = $1 AND time_received >= date_trunc('day', current_date - interval '1'day);", h.IP)
		if err != nil {
			return rs, fmt.Errorf("error fetching count: %w", err)
		}

		h.RequestsCountLastDay = cnt.Count
		ret = append(ret, h)
	}
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return ret, err
}

func (d *KSQLClient) SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error) {
	var rs []models.StoredQuery

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.StoredQuery{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM stored_query", fmt.Sprintf("ORDER BY updated_at DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))

	// For each query, add the tags to the query entry.
	var retQueries []models.StoredQuery
	for _, qEntry := range rs {
		tags, err := d.SearchTagPerQuery(0, 100, fmt.Sprintf("query_id:%d", qEntry.ID))
		if err != nil {
			return rs, fmt.Errorf("cannot get tags for query: %s", err.Error())
		}

		qEntry.TagsToApply = append(qEntry.TagsToApply, tags...)
		retQueries = append(retQueries, qEntry)
	}

	return retQueries, err
}

func (d *KSQLClient) SearchTags(offset int64, limit int64, query string) ([]models.Tag, error) {
	var rs []models.Tag

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Tag{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM tag", fmt.Sprintf("ORDER BY updated_at DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error) {
	var rs []models.Whois

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.Whois{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM whois", fmt.Sprintf("ORDER BY id DESC OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error) {
	var rs []models.TagPerQuery

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.TagPerQuery{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM tag_per_query", fmt.Sprintf(" OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

func (d *KSQLClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error) {
	var rs []models.TagPerRequest

	params, err := ParseQuery(query, getDatamodelDatabaseFields(models.TagPerRequest{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, "FROM tag_per_request", fmt.Sprintf(" OFFSET %d LIMIT %d", offset, limit))
	if err != nil {
		return rs, fmt.Errorf("cannot build query: %s", err.Error())
	}
	slog.Debug("Running query", slog.String("query", query), slog.Int("values", len(values)))
	start := time.Now()
	err = d.db.Query(d.ctx, &rs, query, values...)
	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return rs, err
}

// GetTagPerRequestFullForRequest returns a TagPerRequestFull struct which
// contains a join of the TagPerRequest and Tag structs.
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

func (d *KSQLClient) GetContentRuleByID(id int64) (models.ContentRule, error) {
	cr := models.ContentRule{}
	err := d.db.QueryOne(d.ctx, &cr, "FROM content_rule WHERE id = $1", id)
	return cr, err
}

func (d *KSQLClient) DeleteContentRule(id int64) error {
	return d.db.Delete(d.ctx, ContentRuleTable, id)
}

// FakeDatabaseClient is a struct specifically for testing users of the
// DatabaseClient interface
type FakeDatabaseClient struct {
	ContentIDToReturn         int64
	ContentsToReturn          map[int64]models.Content
	ErrorToReturn             error
	ContentRuleIDToReturn     int64
	ContentRulesToReturn      []models.ContentRule
	RequestsToReturn          []models.Request
	RequestToReturn           models.Request
	DownloadsToReturn         []models.Download
	ApplicationToReturn       models.Application
	HoneypotToReturn          models.Honeypot
	HoneypotErrorToReturn     error
	QueriesToReturn           []models.StoredQuery
	QueriesToReturnError      error
	TagPerQueryReturn         []models.TagPerQuery
	TagPerQueryReturnError    error
	WhoisToReturn             models.Whois
	WhoisErrorToReturn        error
	LastDataModelSeen         interface{}
	LastExternalDataModelSeen interface{}
	P0fResultToReturn         models.P0fResult
	P0fErrorToReturn          error
	IpEventToReturn           models.IpEvent
	DataModelToReturn         models.DataModel
	SessionToReturn           models.Session
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) GetContentRuleByID(id int64) (models.ContentRule, error) {
	return f.ContentRulesToReturn[0], f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (models.Content, error) {
	ct, ok := f.ContentsToReturn[id]
	if !ok {
		return ct, fmt.Errorf("not found")
	}
	return ct, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Insert(dm models.DataModel) (models.DataModel, error) {
	f.LastDataModelSeen = dm
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error) {
	f.LastExternalDataModelSeen = dm
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Update(dm models.DataModel) error {
	f.LastDataModelSeen = dm
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) Delete(dm models.DataModel) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error) {
	return []models.RequestMetadata{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchRequests(offset int64, limit int64, query string) ([]models.Request, error) {
	return []models.Request{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error) {
	return []models.IpEvent{f.IpEventToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error) {
	return f.ContentRulesToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchSession(offset int64, limit int64, query string) ([]models.Session, error) {
	return []models.Session{f.SessionToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContent(offset int64, limit int64, query string) ([]models.Content, error) {
	var ret []models.Content
	for _, v := range f.ContentsToReturn {
		ret = append(ret, v)
	}
	return ret, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetAppByID(id int64) (models.Application, error) {
	return f.ApplicationToReturn, nil
}
func (f *FakeDatabaseClient) SearchApps(offset int64, limit int64, query string) ([]models.Application, error) {
	return []models.Application{f.ApplicationToReturn}, nil
}
func (f *FakeDatabaseClient) SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error) {
	return f.DownloadsToReturn, nil
}
func (f *FakeDatabaseClient) SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error) {
	return []models.Honeypot{f.HoneypotToReturn}, f.HoneypotErrorToReturn
}
func (f *FakeDatabaseClient) SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error) {
	return f.QueriesToReturn, f.QueriesToReturnError
}
func (f *FakeDatabaseClient) SearchTags(offset int64, limit int64, query string) ([]models.Tag, error) {
	return []models.Tag{}, nil
}
func (f *FakeDatabaseClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error) {
	return f.TagPerQueryReturn, f.TagPerQueryReturnError
}
func (f *FakeDatabaseClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error) {
	return []models.TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error) {
	return []models.TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error) {
	return []models.TagPerRequestFull{}, nil
}
func (f *FakeDatabaseClient) GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error) {
	return f.P0fResultToReturn, f.P0fErrorToReturn
}
func (f *FakeDatabaseClient) GetRequestByID(id int64) (models.Request, error) {
	return f.RequestToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error) {
	return []models.Whois{f.WhoisToReturn}, f.WhoisErrorToReturn
}
