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
	"time"

	"loophid/pkg/util"

	"github.com/jackc/pgx/v5/pgtype"
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

type DataModel interface {
	ModelID() int64
}

type Content struct {
	ID          int64                    `ksql:"id,skipInserts" json:"id"           doc:"The ID of the content"`
	Data        []byte                   `ksql:"data"           json:"data"         doc:"The content data itself"`
	Name        string                   `ksql:"name"           json:"name"         doc:"The content name"`
	Description string                   `ksql:"description"    json:"description"  doc:"The content description"`
	ContentType string                   `ksql:"content_type"   json:"content_type" doc:"The HTTP content-type"`
	Server      string                   `ksql:"server"         json:"server"       doc:"The HTTP server with which the content is served"`
	IsDefault   bool                     `ksql:"is_default"     json:"is_default"`
	StatusCode  string                   `ksql:"status_code"    json:"status_code"  doc:"The HTTP status code"`
	Script      string                   `ksql:"script"         json:"script"       doc:"The content script"`
	Headers     pgtype.FlatArray[string] `ksql:"headers"        json:"headers"      doc:"The content HTTP headers"`
	CreatedAt   time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"time.Time of creation"`
	UpdatedAt   time.Time                `ksql:"updated_at,timeNowUTC"              json:"updated_at" doc:"time.Time of last update"`
}

func (c *Content) ModelID() int64 { return c.ID }

type ContentRule struct {
	ID           int64     `ksql:"id,skipInserts" json:"id" doc:"The rule ID"`
	Host         string    `ksql:"host" json:"host"`
	Uri          string    `ksql:"uri" json:"uri"           doc:"The URI matching string"`
	Body         string    `ksql:"body" json:"body"         doc:"The body matching string"`
	Method       string    `ksql:"method" json:"method"     doc:"The HTTP method the rule matches on"`
	Port         int64     `ksql:"port" json:"port"         doc:"The TCP port the rue matches on."`
	UriMatching  string    `ksql:"uri_matching" json:"uri_matching"   doc:"The URI matching method (exact, regex, ..)"`
	BodyMatching string    `ksql:"body_matching" json:"body_matching" doc:"The body matching method"`
	ContentID    int64     `ksql:"content_id" json:"content_id" doc:"The ID of the Content this rule serves"`
	AppID        int64     `ksql:"app_id" json:"app_id"         doc:"The ID of the application for which this rule is"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Creation date of the rule"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Last update date of the rule"`
	Alert        bool      `ksql:"alert" json:"alert" doc:"A bool (0 or 1) indicating if the rule should alert"`
}

func (c *ContentRule) ModelID() int64 { return c.ID }

type Request struct {
	ID             int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the request"`
	Proto          string                   `ksql:"proto" json:"proto" doc:"The HTTP protocol (e.g. HTTP/1.0)"`
	Host           string                   `ksql:"host" json:"host" doc:"The HTTP Host header value"`
	Port           int64                    `ksql:"port" json:"port" doc:"The HTTP server port"`
	Method         string                   `ksql:"method" json:"method" doc:"The HTTP method (e.g. GET, POST, PUT, DELETE, ...)"`
	Uri            string                   `ksql:"uri" json:"uri" doc:"The request URI"`
	Path           string                   `ksql:"path" json:"path" doc:"The URL path"`
	Query          string                   `ksql:"query" json:"query" doc:"The query section of the URL"`
	Referer        string                   `ksql:"referer" json:"referer" doc:"The referer header value"`
	ContentType    string                   `ksql:"content_type" json:"content_type" doc:"The Content-Type header value"`
	ContentLength  int64                    `ksql:"content_length" json:"content_length" doc:"The Content-Length header value"`
	UserAgent      string                   `ksql:"user_agent" json:"user_agent" doc:"The User-Agent value"`
	Headers        pgtype.FlatArray[string] `ksql:"headers" json:"headers" doc:"The client HTTP headers"`
	Body           []byte                   `ksql:"body" json:"body" doc:"The request body"`
	HoneypotIP     string                   `ksql:"honeypot_ip" json:"honeypot_ip" doc:"The honeypot IP that received the request"`
	SourceIP       string                   `ksql:"source_ip" json:"source_ip" doc:"The HTTP client source IP"`
	SourcePort     int64                    `ksql:"source_port" json:"source_port" doc:"The HTTP client source port"`
	Raw            string                   `ksql:"raw" json:"raw" doc:"The raw HTTP request"`
	RawResponse    string                   `ksql:"raw_response" json:"raw_response" doc:"The raw HTTP response (only used for scripted Content)"`
	TimeReceived   time.Time                `ksql:"time_received,skipUpdates" json:"time_received" doc:"The date and time the honeypot received the request"`
	CreatedAt      time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"The date and time of creation"`
	UpdatedAt      time.Time                `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"The date and time of the last update"`
	ContentID      int64                    `ksql:"content_id" json:"content_id" doc:"The Content ID that was served"`
	ContentDynamic bool                     `ksql:"content_dynamic" json:"content_dynamic" doc:"A bool indicating if the Content is dynamic (script based)"`
	RuleID         int64                    `ksql:"rule_id" json:"rule_id" doc:"The ID of the rule that matched this request"`
	Starred        bool                     `ksql:"starred" json:"starred" doc:"A bool if the request is starred"`
	BaseHash       string                   `ksql:"base_hash" json:"base_hash" doc:"A base hash to find similar requests"`
	Tags           []TagPerRequestFull      `json:"tags"`
	P0fResult      P0fResult                `json:"p0f_result"`
}

func (c *Request) ModelID() int64 { return c.ID }

// BodyString returns the body as a string and is used in the javascript
// context for easy access.
func (c *Request) BodyString() string { return string(c.Body) }

type RequestMetadata struct {
	ID        int64     `ksql:"id,skipInserts" json:"id"`
	RequestID int64     `ksql:"request_id" json:"request_id"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	Type      string    `ksql:"type" json:"type"`
	Data      string    `ksql:"data" json:"data"`
}

func (c *RequestMetadata) ModelID() int64 { return c.ID }

// TODO: delete ?
type RequestSourceContent struct {
	SourceIP  string
	ContentID int64
}

type Honeypot struct {
	ID                   int64     `ksql:"id,skipInserts" json:"id" doc:"The ID of the honeypot"`
	IP                   string    `ksql:"ip" json:"ip" doc:"The IP of the honeypot (v4 or v6)"`
	Version              string    `ksql:"version" json:"version" doc:"The honeypot version"`
	AuthToken            string    `ksql:"auth_token" json:"auth_token" doc:"The authentication token"`
	CreatedAt            time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt            time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	LastCheckin          time.Time `ksql:"last_checkin,skipInserts,skipUpdates" json:"last_checkin" doc:"Date and time of last seen"`
	DefaultContentID     int64     `ksql:"default_content_id" json:"default_content_id" doc:"The Content ID that is served by default"`
	RequestsCountLastDay int64     `json:"request_count_last_day"`
}

func (c *Honeypot) ModelID() int64 { return c.ID }

type Application struct {
	ID        int64     `ksql:"id,skipInserts" json:"id" doc:"The ID of the application"`
	Name      string    `ksql:"name" json:"name" doc:"The application name"`
	Version   string    `ksql:"version" json:"version" doc:"The application version"`
	Vendor    string    `ksql:"vendor" json:"vendor" doc:"The application vendor"`
	OS        string    `ksql:"os" json:"os" doc:"The OS on which the application runs"`
	Link      string    `ksql:"link" json:"link" doc:"A reference link"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
}

func (c *Application) ModelID() int64 { return c.ID }

type Download struct {
	ID                      int64                    `ksql:"id,skipInserts" json:"id" doc:"The ID of the download"`
	RequestID               int64                    `ksql:"request_id" json:"request_id" doc:"ID of the request where the download originated from"`
	Size                    int64                    `ksql:"size" json:"size" doc:"Size in bytes of the download"`
	Port                    int64                    `ksql:"port" json:"port" doc:"Server port"`
	CreatedAt               time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	LastSeenAt              time.Time                `ksql:"last_seen_at" json:"last_seen_at" doc:"Date and time of last update"`
	ContentType             string                   `ksql:"content_type" json:"content_type" doc:"The content type (mime) of the download (reported by server)"`
	DetectedContentType     string                   `ksql:"detected_content_type" json:"detected_content_type" doc:"The content type (mime) as detected"`
	OriginalUrl             string                   `ksql:"original_url" json:"original_url" doc:"Original download URL"`
	UsedUrl                 string                   `ksql:"used_url" json:"used_url" doc:"Actually used download URL"`
	IP                      string                   `ksql:"ip" json:"ip" doc:"Download server IP"`
	HoneypotIP              string                   `ksql:"honeypot_ip" json:"honeypot_ip" doc:"Honeypot IP used for download"`
	SHA256sum               string                   `ksql:"sha256sum" json:"sha256sum" doc:"SHA256 sum of the download"`
	Host                    string                   `ksql:"host" json:"host" doc:"The Host header value used in downloading"`
	FileLocation            string                   `ksql:"file_location" json:"file_location" doc:"The file location of the download"`
	TimesSeen               int64                    `ksql:"times_seen" json:"times_seen" doc:"How often this was seen"`
	LastRequestID           int64                    `ksql:"last_request_id" json:"last_request_id" doc:"The request ID of the last request with this download"`
	RawHttpResponse         string                   `ksql:"raw_http_response" json:"raw_http_response" doc:"The HTTP response of the download server"`
	VTURLAnalysisID         string                   `ksql:"vt_url_analysis_id" json:"vt_url_analysis_id" doc:"The virus total URL analysis ID"`
	VTFileAnalysisID        string                   `ksql:"vt_file_analysis_id" json:"vt_file_analysis_id" doc:"The virus total file analysis ID"`
	VTFileAnalysisSubmitted bool                     `ksql:"vt_file_analysis_submitted" json:"vt_file_analysis_submitted"`
	VTFileAnalysisDone      bool                     `ksql:"vt_file_analysis_done" json:"vt_file_analysis_done"`
	VTFileAnalysisResult    pgtype.FlatArray[string] `ksql:"vt_file_analysis_result" json:"vt_file_analysis_result"`
	VTAnalysisHarmless      int64                    `ksql:"vt_analysis_harmless" json:"vt_analysis_harmless" doc:"Virus total results marked harmless"`
	VTAnalysisMalicious     int64                    `ksql:"vt_analysis_malicious" json:"vt_analysis_malicious" doc:"Virus total results marked malicious"`
	VTAnalysisSuspicious    int64                    `ksql:"vt_analysis_suspicious" json:"vt_analysis_suspicious" doc:"Virus total results marked suspicious"`
	VTAnalysisUndetected    int64                    `ksql:"vt_analysis_undetected" json:"vt_analysis_undetected" doc:"Virus total results marked undetected"`
	VTAnalysisTimeout       int64                    `ksql:"vt_analysis_timeout" json:"vt_analysis_timeout"`
}

func (c *Download) ModelID() int64 { return c.ID }

type Whois struct {
	ID        int64     `ksql:"id,skipInserts" json:"id"`
	IP        string    `ksql:"ip" json:"ip"`
	Data      string    `ksql:"data" json:"data"`
	Rdap      []byte    `ksql:"rdap" json:"rdap"`
	Country   string    `ksql:"country" json:"country"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *Whois) ModelID() int64 { return c.ID }

type P0fResult struct {
	ID               int64     `ksql:"id,skipInserts" json:"id"`
	IP               string    `ksql:"ip" json:"ip"`
	FirstSeen        time.Time `ksql:"first_seen_time" json:"first_seen_time"`
	LastSeen         time.Time `ksql:"last_seen_time" json:"last_seen_time"`
	TotalCount       int64     `ksql:"total_count" json:"total_count"`
	UptimeMinutes    int64     `ksql:"uptime_minutes" json:"uptime_minutes"`
	UptimeDays       int64     `ksql:"uptime_days" json:"uptime_days"`
	Distance         int64     `ksql:"distance" json:"distance"`
	LastNatDetection time.Time `ksql:"last_nat_detection_time" json:"last_nat_detection_time"`
	LastOsChange     time.Time `ksql:"last_os_change_time" json:"last_os_change_time"`
	OsMatchQuality   int64     `ksql:"os_match_quality" json:"os_match_quality"`
	OsName           string    `ksql:"os_name" json:"os_name"`
	OsVersion        string    `ksql:"os_version" json:"os_version"`
	HttpName         string    `ksql:"http_name" json:"http_name"`
	HttpFlavor       string    `ksql:"http_flavor" json:"http_flavor"`
	Language         string    `ksql:"language" json:"language"`
	LinkType         string    `ksql:"link_type" json:"link_type"`
	CreatedAt        time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt        time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *P0fResult) ModelID() int64 { return c.ID }

type StoredQuery struct {
	ID          int64         `ksql:"id,skipInserts" json:"id" doc:"The ID of the query"`
	Query       string        `ksql:"query" json:"query" doc:"The query itself"`
	Description string        `ksql:"description" json:"description" doc:"A description of the query"`
	CreatedAt   time.Time     `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt   time.Time     `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
	LastRanAt   time.Time     `ksql:"last_ran_at" json:"last_ran_at" doc:"Date and time the last time the query ran"`
	RecordCount int64         `ksql:"record_count" json:"record_count"`
	TagsToApply []TagPerQuery `json:"tags_to_apply"`
}

func (c *StoredQuery) ModelID() int64 { return c.ID }

type Tag struct {
	ID          int64     `ksql:"id,skipInserts" json:"id" doc:"The ID of the tag"`
	Name        string    `ksql:"name" json:"name" doc:"The name of the tag"`
	ColorHtml   string    `ksql:"color_html" json:"color_html" doc:"HTML color code"`
	Description string    `ksql:"description" json:"description" doc:"A description of the tag"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at" doc:"Date and time of creation"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at" doc:"Date and time of last update"`
}

func (c *Tag) ModelID() int64 { return c.ID }

type TagPerQuery struct {
	ID      int64 `ksql:"id,skipInserts" json:"id"`
	TagID   int64 `ksql:"tag_id" json:"tag_id"`
	QueryID int64 `ksql:"query_id" json:"query_id"`
}

func (c *TagPerQuery) ModelID() int64 { return c.ID }

type TagPerRequest struct {
	ID            int64 `ksql:"id,skipInserts" json:"id"`
	TagID         int64 `ksql:"tag_id" json:"tag_id"`
	RequestID     int64 `ksql:"request_id" json:"request_id"`
	TagPerQueryID int64 `ksql:"tag_per_query_id" json:"tag_per_query_id"`
}

func (c *TagPerRequest) ModelID() int64 { return c.ID }

type TagPerRequestFull struct {
	TagPerRequest TagPerRequest `tablename:"tag_per_request" json:"tag_per_request"`
	Tag           Tag           `tablename:"tag" json:"tag"`
}

type DatabaseClient interface {
	Close()
	Insert(dm DataModel) (DataModel, error)
	Update(dm DataModel) error
	Delete(dm DataModel) error
	GetApps() ([]Application, error)
	GetAppByID(id int64) (Application, error)
	SearchApps(offset int64, limit int64, query string) ([]Application, error)
	GetContentByID(id int64) (Content, error)
	GetContent() ([]Content, error)
	GetContentRuleByID(id int64) (ContentRule, error)
	GetContentRules() ([]ContentRule, error)
	GetDownloads() ([]Download, error)
	GetDownloadBySum(sha256sum string) (Download, error)
	GetHoneypotByIP(ip string) (Honeypot, error)
	GetWhoisByIP(ip string) (Whois, error)
	GetP0fResultByIP(ip string, querySuffix string) (P0fResult, error)
	GetHoneypots() ([]Honeypot, error)
	GetRequests() ([]Request, error)
	GetRequestsForSourceIP(ip string) ([]Request, error)
	GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error)
	SearchRequests(offset int64, limit int64, query string) ([]Request, error)
	SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error)
	SearchContent(offset int64, limit int64, query string) ([]Content, error)
	SearchDownloads(offset int64, limit int64, query string) ([]Download, error)
	SearchHoneypots(offset int64, limit int64, query string) ([]Honeypot, error)
	SearchStoredQuery(offset int64, limit int64, query string) ([]StoredQuery, error)
	SearchTags(offset int64, limit int64, query string) ([]Tag, error)
	SearchTagPerQuery(offset int64, limit int64, query string) ([]TagPerQuery, error)
	SearchTagPerRequest(offset int64, limit int64, query string) ([]TagPerRequest, error)
	GetTagPerRequestFullForRequest(id int64) ([]TagPerRequestFull, error)
	GetTagsPerRequestForRequestID(id int64) ([]TagPerRequest, error)
	GetRequestsDistinctComboLastMonth() ([]Request, error)
	GetMetadataByRequestID(id int64) ([]RequestMetadata, error)
}

// Helper function to get database field names.
func getDatamodelDatabaseFields(datamodel interface{}) []string {
	var ret []string
	t := reflect.TypeOf(datamodel)
	for i := 0; i < t.NumField(); i++ {
		tvalue := t.Field(i).Tag.Get("ksql")
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

func (d *KSQLClient) getTableForModel(dm DataModel) *ksql.Table {
	name := util.GetStructName(dm)

	switch name {
	case "Application":
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
	default:
		fmt.Printf("Don't know %s datamodel\n", name)
		return nil
	}
}

func (d *KSQLClient) Insert(dm DataModel) (DataModel, error) {
	t := d.getTableForModel(dm)
	if t == nil {
		return dm, fmt.Errorf("unknown datamodel: %v", dm)
	}
	err := d.db.Insert(d.ctx, *t, dm)
	return dm, err
}

func (d *KSQLClient) Update(dm DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("unknown datamodel: %v", dm)
	}
	return d.db.Patch(d.ctx, *t, dm)
}

func (d *KSQLClient) Delete(dm DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("unknown datamodel: %v", dm)
	}
	return d.db.Delete(d.ctx, *t, dm.ModelID())
}

func (d *KSQLClient) GetAppByID(id int64) (Application, error) {
	ap := Application{}
	err := d.db.QueryOne(d.ctx, &ap, fmt.Sprintf("FROM app WHERE id = %d", id))
	if ap.ID == 0 {
		return ap, fmt.Errorf("found no app for ID: %d", id)
	}
	return ap, err
}

func (d *KSQLClient) GetApps() ([]Application, error) {
	var apps []Application
	err := d.db.Query(d.ctx, &apps, "FROM app ORDER BY name")
	return apps, err
}

func (d *KSQLClient) GetDownloads() ([]Download, error) {
	var dls []Download
	err := d.db.Query(d.ctx, &dls, "FROM downloads ORDER BY created_at DESC")
	return dls, err
}

func (d *KSQLClient) GetDownloadBySum(sha256sum string) (Download, error) {
	var dl Download
	err := d.db.QueryOne(d.ctx, &dl, "FROM downloads WHERE sha256sum = $1", sha256sum)
	if dl.ID == 0 {
		return dl, fmt.Errorf("found no download for hash: %s, %w", sha256sum, err)
	}
	return dl, err
}

func (d *KSQLClient) GetHoneypotByIP(ip string) (Honeypot, error) {
	hp := Honeypot{}
	err := d.db.QueryOne(d.ctx, &hp, "FROM honeypot WHERE ip = $1", ip)
	return hp, err
}

func (d *KSQLClient) GetHoneypots() ([]Honeypot, error) {
	var rs []Honeypot
	err := d.db.Query(d.ctx, &rs, "FROM honeypot")

	var ret []Honeypot
	type Count struct {
		Count int64 `ksql:"cnt"`
	}
	for _, h := range rs {
		var cnt Count
		err = d.db.QueryOne(d.ctx, &cnt, "SELECT COUNT(*) as cnt FROM request WHERE honeypot_ip = $1", h.IP)
		if err != nil {
			return rs, fmt.Errorf("error fetching count: %w", err)
		}

		h.RequestsCountLastDay = cnt.Count
		ret = append(ret, h)
	}
	return ret, err
}

func (d *KSQLClient) GetWhoisByIP(ip string) (Whois, error) {
	hp := Whois{}
	err := d.db.QueryOne(d.ctx, &hp, "FROM whois WHERE ip = $1", ip)
	return hp, err
}

func (d *KSQLClient) GetP0fResultByIP(ip string, querySuffix string) (P0fResult, error) {
	hp := P0fResult{}
	err := d.db.QueryOne(d.ctx, &hp, fmt.Sprintf("FROM p0f_result WHERE ip = $1 %s", querySuffix), ip)
	return hp, err
}

func (d *KSQLClient) GetTagsPerRequestForRequestID(id int64) ([]TagPerRequest, error) {
	var tags []TagPerRequest
	err := d.db.Query(d.ctx, &tags, "FROM tag_per_request WHERE request_id = $1", id)
	return tags, err
}

func (d *KSQLClient) GetRequests() ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "FROM request ORDER BY time_received")
	return rs, err
}

func (d *KSQLClient) GetRequestsForSourceIP(ip string) ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "FROM request WHERE source_ip = $1 ORDER BY time_received", ip)
	return rs, err
}

func (d *KSQLClient) GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error) {
	var rs []Request
	var err error
	if source_ip != nil {
		err = d.db.Query(d.ctx, &rs, "FROM request WHERE source_ip = $1 ORDER BY time_received DESC OFFSET $2 LIMIT $3", *source_ip, offset, limit)
	} else {
		err = d.db.Query(d.ctx, &rs, "FROM request ORDER BY time_received DESC OFFSET $1 LIMIT $2", offset, limit)
	}
	return rs, err
}

func (d *KSQLClient) SearchRequests(offset int64, limit int64, query string) ([]Request, error) {
	var rs []Request

	allowedFields := getDatamodelDatabaseFields(Request{})
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

	var ret []Request
	uniqueIPs := make(map[string]P0fResult)
	// TODO: make this concurrent
	for _, req := range rs {
		tags, err := d.GetTagPerRequestFullForRequest(req.ID)
		if err != nil {
			slog.Warn("error getting tags for request", slog.String("error", err.Error()))
			req.Tags = []TagPerRequestFull{}
		} else {
			req.Tags = append(req.Tags, tags...)
		}

		// Get the p0f result from the database. If there is none, then create a new
		// one (empty)
		pr, ok := uniqueIPs[req.SourceIP]
		if !ok {
			pr, err = d.GetP0fResultByIP(req.SourceIP, "LIMIT 1")
			if err == nil {
				req.P0fResult = pr
			} else {
				req.P0fResult = P0fResult{}
			}
		} else {
			req.P0fResult = pr
		}

		ret = append(ret, req)
	}

	elapsed := time.Since(start)
	slog.Debug("query took", slog.String("elapsed", elapsed.String()))
	return ret, err
}

func (d *KSQLClient) SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error) {
	var rs []ContentRule

	params, err := ParseQuery(query, getDatamodelDatabaseFields(ContentRule{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildComposedQuery(params, fmt.Sprintf("FROM (SELECT * FROM content_rule ORDER BY updated_at DESC OFFSET %d LIMIT %d) AS subq ", offset, limit), "ORDER BY app_id")
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

func (d *KSQLClient) SearchContent(offset int64, limit int64, query string) ([]Content, error) {
	var rs []Content

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Content{}))
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

func (d *KSQLClient) SearchApps(offset int64, limit int64, query string) ([]Application, error) {
	var rs []Application

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Application{}))
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

func (d *KSQLClient) SearchDownloads(offset int64, limit int64, query string) ([]Download, error) {
	var rs []Download

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Download{}))
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

func (d *KSQLClient) SearchHoneypots(offset int64, limit int64, query string) ([]Honeypot, error) {
	var rs []Honeypot

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Honeypot{}))
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

	var ret []Honeypot
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

func (d *KSQLClient) SearchStoredQuery(offset int64, limit int64, query string) ([]StoredQuery, error) {
	var rs []StoredQuery

	params, err := ParseQuery(query, getDatamodelDatabaseFields(StoredQuery{}))
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
	var retQueries []StoredQuery
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

func (d *KSQLClient) SearchTags(offset int64, limit int64, query string) ([]Tag, error) {
	var rs []Tag

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Tag{}))
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

func (d *KSQLClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]TagPerQuery, error) {
	var rs []TagPerQuery

	params, err := ParseQuery(query, getDatamodelDatabaseFields(TagPerQuery{}))
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

func (d *KSQLClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]TagPerRequest, error) {
	var rs []TagPerRequest

	params, err := ParseQuery(query, getDatamodelDatabaseFields(TagPerRequest{}))
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
func (d *KSQLClient) GetTagPerRequestFullForRequest(id int64) ([]TagPerRequestFull, error) {
	var md []TagPerRequestFull
	err := d.db.Query(d.ctx, &md, "FROM tag_per_request JOIN tag ON tag.id = tag_per_request.tag_id AND tag_per_request.request_id = $1", id)
	return md, err
}

func (d *KSQLClient) GetMetadataByRequestID(id int64) ([]RequestMetadata, error) {
	var md []RequestMetadata
	err := d.db.Query(d.ctx, &md, "FROM request_metadata WHERE request_id = $1 ORDER BY type", id)
	return md, err
}

func (d *KSQLClient) GetRequestsDistinctComboLastMonth() ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "SELECT DISTINCT source_ip, content_id, rule_id FROM request WHERE content_id > 0 AND time_received >= date_trunc('month', current_date - interval '1'month);")
	return rs, err
}

func (d *KSQLClient) GetContentByID(id int64) (Content, error) {
	ct := Content{}
	err := d.db.QueryOne(d.ctx, &ct, "FROM content WHERE id = $1", id)
	if ct.ID == 0 {
		return ct, fmt.Errorf("found no content for ID: %d", id)
	}
	return ct, err
}

func (d *KSQLClient) GetContent() ([]Content, error) {
	var cts []Content
	err := d.db.Query(d.ctx, &cts, "FROM content")
	return cts, err
}

func (d *KSQLClient) GetContentRuleByID(id int64) (ContentRule, error) {
	cr := ContentRule{}
	err := d.db.QueryOne(d.ctx, &cr, "FROM content_rule WHERE id = $1", id)
	return cr, err
}

func (d *KSQLClient) GetContentRules() ([]ContentRule, error) {
	var cts []ContentRule
	err := d.db.Query(d.ctx, &cts, "FROM content_rule ORDER BY app_id DESC")
	return cts, err
}

func (d *KSQLClient) DeleteContentRule(id int64) error {
	return d.db.Delete(d.ctx, ContentRuleTable, id)
}

// FakeDatabaseClient is a struct specifically for testing users of the
// DatabaseClient interface
type FakeDatabaseClient struct {
	ContentIDToReturn      int64
	ContentsToReturn       map[int64]Content
	ErrorToReturn          error
	ContentRuleIDToReturn  int64
	ContentRulesToReturn   []ContentRule
	RequestsToReturn       []Request
	DownloadsToReturn      []Download
	ApplicationToReturn    Application
	HoneypotToReturn       Honeypot
	HoneypotErrorToReturn  error
	QueriesToReturn        []StoredQuery
	QueriesToReturnError   error
	TagPerQueryReturn      []TagPerQuery
	TagPerQueryReturnError error
	WhoisToReturn          Whois
	WhoisErrorToReturn     error
	LastDataModelSeen      interface{}
	P0fResultToReturn      P0fResult
	P0fErrorToReturn       error
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) GetContentRuleByID(id int64) (ContentRule, error) {
	return f.ContentRulesToReturn[0], f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (Content, error) {
	ct, ok := f.ContentsToReturn[id]
	if !ok {
		return ct, fmt.Errorf("not found")
	}
	return ct, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContent() ([]Content, error) {
	var ret []Content
	for _, v := range f.ContentsToReturn {
		ret = append(ret, v)
	}
	return ret, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentRules() ([]ContentRule, error) {
	return f.ContentRulesToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetRequests() ([]Request, error) {
	return []Request{}, nil
}
func (f *FakeDatabaseClient) GetRequestsForSourceIP(ip string) ([]Request, error) {
	return []Request{}, nil
}
func (f *FakeDatabaseClient) GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error) {
	return []Request{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Insert(dm DataModel) (DataModel, error) {
	f.LastDataModelSeen = dm
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Update(dm DataModel) error {
	f.LastDataModelSeen = dm
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetApps() ([]Application, error) {
	return []Application{f.ApplicationToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetHoneypotByIP(ip string) (Honeypot, error) {
	return f.HoneypotToReturn, f.HoneypotErrorToReturn
}
func (f *FakeDatabaseClient) GetHoneypots() ([]Honeypot, error) {
	return []Honeypot{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Delete(dm DataModel) error {
	return f.ErrorToReturn
}

func (f *FakeDatabaseClient) GetRequestsDistinctComboLastMonth() ([]Request, error) {
	return f.RequestsToReturn, nil
}
func (f *FakeDatabaseClient) GetMetadataByRequestID(id int64) ([]RequestMetadata, error) {
	return []RequestMetadata{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchRequests(offset int64, limit int64, query string) ([]Request, error) {
	return []Request{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error) {
	return f.ContentRulesToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContent(offset int64, limit int64, query string) ([]Content, error) {
	var ret []Content
	for _, v := range f.ContentsToReturn {
		ret = append(ret, v)
	}
	return ret, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetDownloads() ([]Download, error) {
	return f.DownloadsToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetDownloadBySum(sha256sum string) (Download, error) {
	if f.DownloadsToReturn != nil && len(f.DownloadsToReturn) > 0 {
		return f.DownloadsToReturn[0], f.ErrorToReturn
	}
	return Download{}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetAppByID(id int64) (Application, error) {
	return f.ApplicationToReturn, nil
}
func (f *FakeDatabaseClient) SearchApps(offset int64, limit int64, query string) ([]Application, error) {
	return []Application{f.ApplicationToReturn}, nil
}
func (f *FakeDatabaseClient) SearchDownloads(offset int64, limit int64, query string) ([]Download, error) {
	return f.DownloadsToReturn, nil
}
func (f *FakeDatabaseClient) SearchHoneypots(offset int64, limit int64, query string) ([]Honeypot, error) {
	return []Honeypot{f.HoneypotToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetWhoisByIP(ip string) (Whois, error) {
	return Whois{}, f.WhoisErrorToReturn
}
func (f *FakeDatabaseClient) SearchStoredQuery(offset int64, limit int64, query string) ([]StoredQuery, error) {
	return f.QueriesToReturn, f.QueriesToReturnError
}
func (f *FakeDatabaseClient) SearchTags(offset int64, limit int64, query string) ([]Tag, error) {
	return []Tag{}, nil
}
func (f *FakeDatabaseClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]TagPerQuery, error) {
	return f.TagPerQueryReturn, f.TagPerQueryReturnError
}
func (f *FakeDatabaseClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]TagPerRequest, error) {
	return []TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagsPerRequestForRequestID(id int64) ([]TagPerRequest, error) {
	return []TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagPerRequestFullForRequest(id int64) ([]TagPerRequestFull, error) {
	return []TagPerRequestFull{}, nil
}
func (f *FakeDatabaseClient) GetP0fResultByIP(ip string, querySuffix string) (P0fResult, error) {
	return f.P0fResultToReturn, f.P0fErrorToReturn
}
