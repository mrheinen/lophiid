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

type DataModel interface {
	ModelID() int64
}

type Content struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	Data        []byte    `ksql:"data"           json:"data"`
	Name        string    `ksql:"name"           json:"name"`
	Description string    `ksql:"description"    json:"description"`
	ContentType string    `ksql:"content_type"   json:"content_type"`
	Server      string    `ksql:"server"         json:"server"`
	IsDefault   bool      `ksql:"is_default"     json:"is_default"`
	StatusCode  string    `ksql:"status_code"    json:"status_code"`
	Script      string    `ksql:"script"         json:"script"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC"              json:"updated_at"`
}

func (c *Content) ModelID() int64 { return c.ID }

type ContentRule struct {
	ID           int64     `ksql:"id,skipInserts" json:"id"`
	Host         string    `ksql:"host" json:"host"`
	Uri          string    `ksql:"uri" json:"uri"`
	UriMatching  string    `ksql:"uri_matching" json:"uri_matching"`
	Body         string    `ksql:"body" json:"body"`
	BodyMatching string    `ksql:"body_matching" json:"body_matching"`
	Method       string    `ksql:"method" json:"method"`
	ContentID    int64     `ksql:"content_id" json:"content_id"`
	Port         int64     `ksql:"port" json:"port"`
	AppID        int64     `ksql:"app_id" json:"app_id"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	Alert        bool      `ksql:"alert" json:"alert"`
}

func (c *ContentRule) ModelID() int64 { return c.ID }

type Request struct {
	ID             int64               `ksql:"id,skipInserts" json:"id"`
	Proto          string              `ksql:"proto" json:"proto"`
	Host           string              `ksql:"host" json:"host"`
	Port           int64               `ksql:"port" json:"port"`
	Method         string              `ksql:"method" json:"method"`
	Uri            string              `ksql:"uri" json:"uri"`
	Path           string              `ksql:"path" json:"path"`
	Referer        string              `ksql:"referer" json:"referer"`
	ContentLength  int64               `ksql:"content_length" json:"content_length"`
	UserAgent      string              `ksql:"user_agent" json:"user_agent"`
	Body           []byte              `ksql:"body" json:"body"`
	HoneypotIP     string              `ksql:"honeypot_ip" json:"honeypot_ip"`
	SourceIP       string              `ksql:"source_ip" json:"source_ip"`
	SourcePort     int64               `ksql:"source_port" json:"source_port"`
	Raw            string              `ksql:"raw" json:"raw"`
	RawResponse    string              `ksql:"raw_response" json:"raw_response"`
	TimeReceived   time.Time           `ksql:"time_received,skipUpdates" json:"time_received"`
	CreatedAt      time.Time           `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt      time.Time           `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	ContentID      int64               `ksql:"content_id" json:"content_id"`
	ContentDynamic bool                `ksql:"content_dynamic" json:"content_dynamic"`
	RuleID         int64               `ksql:"rule_id" json:"rule_id"`
	Starred        bool                `ksql:"starred" json:"starred"`
	Tags           []TagPerRequestFull `json:"tags"`
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
	ID                   int64     `ksql:"id,skipInserts" json:"id"`
	IP                   string    `ksql:"ip" json:"ip"`
	CreatedAt            time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt            time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	LastCheckin          time.Time `ksql:"last_checkin,skipInserts,skipUpdates" json:"last_checkin"`
	DefaultContentID     int64     `ksql:"default_content_id" json:"default_content_id"`
	RequestsCountLastDay int64     `json:"request_count_last_day"`
}

func (c *Honeypot) ModelID() int64 { return c.ID }

type Application struct {
	ID        int64     `ksql:"id,skipInserts" json:"id"`
	Name      string    `ksql:"name" json:"name"`
	Version   string    `ksql:"version" json:"version"`
	Vendor    string    `ksql:"vendor" json:"vendor"`
	OS        string    `ksql:"os" json:"os"`
	Link      string    `ksql:"link" json:"link"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *Application) ModelID() int64 { return c.ID }

type Download struct {
	ID                      int64                    `ksql:"id,skipInserts" json:"id"`
	RequestID               int64                    `ksql:"request_id" json:"request_id"`
	Size                    int64                    `ksql:"size" json:"size"`
	Port                    int64                    `ksql:"port" json:"port"`
	CreatedAt               time.Time                `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	LastSeenAt              time.Time                `ksql:"last_seen_at" json:"last_seen_at"`
	ContentType             string                   `ksql:"content_type" json:"content_type"`
	OriginalUrl             string                   `ksql:"original_url" json:"original_url"`
	UsedUrl                 string                   `ksql:"used_url" json:"used_url"`
	IP                      string                   `ksql:"ip" json:"ip"`
	SHA256sum               string                   `ksql:"sha256sum" json:"sha256sum"`
	Host                    string                   `ksql:"host" json:"host"`
	FileLocation            string                   `ksql:"file_location" json:"file_location"`
	TimesSeen               int64                    `ksql:"times_seen" json:"times_seen"`
	LastRequestID           int64                    `ksql:"last_request_id" json:"last_request_id"`
	RawHttpResponse         string                   `ksql:"raw_http_response" json:"raw_http_response"`
	VTURLAnalysisID         string                   `ksql:"vt_url_analysis_id" json:"vt_url_analysis_id"`
	VTFileAnalysisID        string                   `ksql:"vt_file_analysis_id" json:"vt_file_analysis_id"`
	VTFileAnalysisSubmitted bool                     `ksql:"vt_file_analysis_submitted" json:"vt_file_analysis_submitted"`
	VTFileAnalysisDone      bool                     `ksql:"vt_file_analysis_done" json:"vt_file_analysis_done"`
	VTFileAnalysisResult    pgtype.FlatArray[string] `ksql:"vt_file_analysis_result" json:"vt_file_analysis_result"`
	VTAnalysisHarmless      int64                    `ksql:"vt_analysis_harmless" json:"vt_analysis_harmless"`
	VTAnalysisMalicious     int64                    `ksql:"vt_analysis_malicious" json:"vt_analysis_malicious"`
	VTAnalysisSuspicious    int64                    `ksql:"vt_analysis_suspicious" json:"vt_analysis_suspicious"`
	VTAnalysisUndetected    int64                    `ksql:"vt_analysis_undetected" json:"vt_analysis_undetected"`
	VTAnalysisTimeout       int64                    `ksql:"vt_analysis_timeout" json:"vt_analysis_timeout"`
}

func (c *Download) ModelID() int64 { return c.ID }

type Whois struct {
	ID        int64     `ksql:"id,skipInserts" json:"id"`
	IP        string    `ksql:"ip" json:"ip"`
	Data      string    `ksql:"data" json:"data"`
	CreatedAt time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *Whois) ModelID() int64 { return c.ID }

type StoredQuery struct {
	ID          int64         `ksql:"id,skipInserts" json:"id"`
	Query       string        `ksql:"query" json:"query"`
	Description string        `ksql:"description" json:"description"`
	CreatedAt   time.Time     `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt   time.Time     `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	LastRanAt   time.Time     `ksql:"last_ran_at" json:"last_ran_at"`
	RecordCount int64         `ksql:"record_count" json:"record_count"`
	TagsToApply []TagPerQuery `json:"tags_to_apply"`
}

func (c *StoredQuery) ModelID() int64 { return c.ID }

type Tag struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	Name        string    `ksql:"name" json:"name"`
	ColorHtml   string    `ksql:"color_html" json:"color_html"`
	Description string    `ksql:"description" json:"description"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
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
	for _, req := range rs {
		tags, err := d.GetTagPerRequestFullForRequest(req.ID)
		if err != nil {
			slog.Warn("error getting tags for request", slog.String("error", err.Error()))
			req.Tags = []TagPerRequestFull{}
		} else {
			req.Tags = append(req.Tags, tags...)
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

	query, values, err := buildComposedQuery(params, "FROM content_rule", fmt.Sprintf("ORDER BY app_id,created_at DESC OFFSET %d LIMIT %d", offset, limit))
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

	query, values, err := buildComposedQuery(params, "FROM app", fmt.Sprintf("OFFSET %d LIMIT %d", offset, limit))
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
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Update(dm DataModel) error {
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
	return f.DownloadsToReturn[0], f.ErrorToReturn
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
	return []Honeypot{}, nil
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
