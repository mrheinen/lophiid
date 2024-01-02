package database

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")
var AppTable = ksql.NewTable("app")
var RequestMetadataTable = ksql.NewTable("request_metadata")
var DownloadTable = ksql.NewTable("downloads")

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
	StatusCode  string    `ksql:"status_code"    json:"status_code"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC"  json:"updated_at"`
}

func (c *Content) ModelID() int64 { return c.ID }

type ContentRule struct {
	ID           int64     `ksql:"id,skipInserts" json:"id"`
	Path         string    `ksql:"path" json:"path"`
	PathMatching string    `ksql:"path_matching" json:"path_matching"`
	Body         string    `ksql:"body" json:"body"`
	BodyMatching string    `ksql:"body_matching" json:"body_matching"`
	Method       string    `ksql:"method" json:"method"`
	ContentID    int64     `ksql:"content_id" json:"content_id"`
	Port         int64     `ksql:"port" json:"port"`
	AppID        int64     `ksql:"app_id" json:"app_id"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

func (c *ContentRule) ModelID() int64 { return c.ID }

type Request struct {
	ID            int64     `ksql:"id,skipInserts" json:"id"`
	Proto         string    `ksql:"proto" json:"proto"`
	Host          string    `ksql:"host" json:"host"`
	Port          int64     `ksql:"port" json:"port"`
	Method        string    `ksql:"method" json:"method"`
	Uri           string    `ksql:"uri" json:"uri"`
	Path          string    `ksql:"path" json:"path"`
	Referer       string    `ksql:"referer" json:"referer"`
	ContentLength int64     `ksql:"content_length" json:"content_length"`
	UserAgent     string    `ksql:"user_agent" json:"user_agent"`
	Body          []byte    `ksql:"body" json:"body"`
	HoneypotIP    string    `ksql:"honeypot_ip" json:"honeypot_ip"`
	SourceIP      string    `ksql:"source_ip" json:"source_ip"`
	SourcePort    int64     `ksql:"source_port" json:"source_port"`
	Raw           string    `ksql:"raw" json:"raw"`
	TimeReceived  time.Time `ksql:"time_received,skipUpdates" json:"time_received"`
	CreatedAt     time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt     time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	ContentID     int64     `ksql:"content_id" json:"content_id"`
	RuleID        int64     `ksql:"rule_id" json:"rule_id"`
}

func (c *Request) ModelID() int64 { return c.ID }

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
	ID           int64     `ksql:"id,skipInserts" json:"id"`
	RequestID    int64     `ksql:"request_id" json:"request_id"`
	Size         int64     `ksql:"size" json:"size"`
	Port         int64     `ksql:"port" json:"port"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	LastSeenAt   time.Time `ksql:"last_seen_at,timeNowUTC" json:"last_seen_at"`
	ContentType  string    `ksql:"content_type" json:"content_type"`
	OriginalUrl  string    `ksql:"original_url" json:"original_url"`
	UsedUrl      string    `ksql:"used_url" json:"used_url"`
	IP           string    `ksql:"ip" json:"ip"`
	SHA256sum    string    `ksql:"sha256sum" json:"sha265sum"`
	Host         string    `ksql:"host" json:"host"`
	FileLocation string    `ksql:"file_location" json:"file_location"`
	TimesSeen    int64     `ksql:"times_seen" json:"times_seen"`
}

func (c *Download) ModelID() int64 { return c.ID }

type DatabaseClient interface {
	Close()
	Insert(dm DataModel) (DataModel, error)
	Update(dm DataModel) error
	Delete(dm DataModel) error
	GetApps() ([]Application, error)
	GetContentByID(id int64) (Content, error)
	GetContent() ([]Content, error)
	GetContentRuleByID(id int64) (ContentRule, error)
	GetContentRules() ([]ContentRule, error)
	GetDownloads() ([]Download, error)
	GetDownloadBySum(sha256sum string) (Download, error)
	GetRequests() ([]Request, error)
	GetRequestsForSourceIP(ip string) ([]Request, error)
	GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error)
	SearchRequests(offset int64, limit int64, query string) ([]Request, error)
	SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error)
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

// db, err := kpgx.New(ctx, "postgres://lo:test@localhost/lophiid", ksql.Config{
func (d *KSQLClient) Init(connectString string) error {

	db, err := kpgx.New(d.ctx, connectString, ksql.Config{
		MaxOpenConns: 3,
	})

	d.db = &db
	return err
}

func (d *KSQLClient) Close() {
	if d.db == nil {
		fmt.Printf("Cannot close closed db")
		return
	}
	d.db.Close()
}

func (d *KSQLClient) getTableForModel(dm DataModel) *ksql.Table {
	var name string
	if t := reflect.TypeOf(dm); t.Kind() == reflect.Ptr {
		name = t.Elem().Name()
	} else {
		name = t.Name()
	}

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
	return dl, err
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

type WhereType int64

const (
	IS WhereType = iota
	LIKE
	GREATER_THAN
	LOWER_THAN
)

type SearchRequestsParam struct {
	key      string
	value    string
	matching WhereType
}

func parseQuery(q string, validFields []string) ([]SearchRequestsParam, error) {
	var ret []SearchRequestsParam

	type RegexByWhereType struct {
		regex     *regexp.Regexp
		splitChar string
		whereType WhereType
	}

	rSearches := []RegexByWhereType{
		{
			regex:     regexp.MustCompile(`[a-z\_]*:[a-zA-Z0-9\._\-%:]*`),
			splitChar: ":",
			whereType: IS,
		},
		{
			regex:     regexp.MustCompile(`[a-z\_]*~[a-zA-Z0-9\._\-%:]*`),
			splitChar: "~",
			whereType: LIKE,
		},
		{
			regex:     regexp.MustCompile(`[a-z\_]*>[0-9]*`),
			splitChar: ">",
			whereType: GREATER_THAN,
		},
		{
			regex:     regexp.MustCompile(`[a-z\_]*[<0-9]*`),
			splitChar: "<",
			whereType: LOWER_THAN,
		},
	}

	for _, regConf := range rSearches {
		for _, part := range regConf.regex.FindAllString(q, -1) {
			options := strings.SplitN(part, regConf.splitChar, 2)
			if len(options) != 2 {
				continue
			}

			hasField := false
			for _, v := range validFields {
				if v == options[0] {
					hasField = true
					break
				}
			}

			if !hasField {
				return ret, fmt.Errorf("unknown search option: %s", part)
			} else {
				ret = append(ret, SearchRequestsParam{
					key:      options[0],
					value:    options[1],
					matching: regConf.whereType,
				})
			}
		}
	}

	if len(ret) == 0 {
		slog.Debug("Search did not parse", slog.String("query", q))
	}
	return ret, nil
}

func getWhereClause(index int, s *SearchRequestsParam) (string, error) {
	switch s.matching {
	case IS:
		return fmt.Sprintf("%s = $%d ", s.key, index), nil
	case LIKE:
		if !strings.Contains(s.value, "%") {
			s.value = fmt.Sprintf("%s%%", s.value)
		}
		return fmt.Sprintf("%s LIKE $%d ", s.key, index), nil
	case LOWER_THAN:
		return fmt.Sprintf("%s < $%d ", s.key, index), nil
	case GREATER_THAN:
		return fmt.Sprintf("%s > $%d ", s.key, index), nil
	}

	return "", fmt.Errorf("could not match %+v", s)
}

func buildQuery(params []SearchRequestsParam, queryPrefix string, querySuffix string) (string, []interface{}, error) {
	baseQuery := queryPrefix

	idx := 1
	var values []interface{}
	for _, param := range params {
		wc, err := getWhereClause(idx, &param)
		if err != nil {
			return "", nil, err
		}
		if idx == 1 {
			baseQuery = fmt.Sprintf("%s WHERE %s", baseQuery, wc)
			values = append(values, param.value)
		} else {
			baseQuery = fmt.Sprintf("%s AND %s", baseQuery, wc)
			values = append(values, param.value)
		}
		idx++
	}

	baseQuery = fmt.Sprintf("%s %s", baseQuery, querySuffix)
	return baseQuery, values, nil
}

func (d *KSQLClient) SearchRequests(offset int64, limit int64, query string) ([]Request, error) {
	var rs []Request

	params, err := parseQuery(query, getDatamodelDatabaseFields(Request{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildQuery(params, "FROM request", fmt.Sprintf("ORDER BY time_received DESC OFFSET %d LIMIT %d", offset, limit))
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

func (d *KSQLClient) SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error) {
	var rs []ContentRule

	params, err := parseQuery(query, getDatamodelDatabaseFields(ContentRule{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildQuery(params, "FROM content_rule", fmt.Sprintf("ORDER BY app_id DESC OFFSET %d LIMIT %d", offset, limit))
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
	err := d.db.QueryOne(d.ctx, &ct, fmt.Sprintf("FROM content WHERE id = %d", id))
	return ct, err
}

func (d *KSQLClient) GetContent() ([]Content, error) {
	var cts []Content
	err := d.db.Query(d.ctx, &cts, "FROM content")
	return cts, err
}

func (d *KSQLClient) GetContentRuleByID(id int64) (ContentRule, error) {
	cr := ContentRule{}
	err := d.db.QueryOne(d.ctx, &cr, fmt.Sprintf("FROM content_rule WHERE id = %d", id))
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
	ContentIDToReturn     int64
	ContentsToReturn      map[int64]Content
	ErrorToReturn         error
	ContentRuleIDToReturn int64
	ContentRulesToReturn  []ContentRule
	RequestsToReturn      []Request
	DownloadsToReturn     []Download
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) GetContentRuleByID(id int64) (ContentRule, error) {
	return f.ContentRulesToReturn[0], f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (Content, error) {
	return f.ContentsToReturn[id], f.ErrorToReturn
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
	return []Application{}, f.ErrorToReturn
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
func (f *FakeDatabaseClient) GetDownloads() ([]Download, error) {
	return f.DownloadsToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetDownloadBySum(sha256sum string) (Download, error) {
	return f.DownloadsToReturn[0], f.ErrorToReturn
}
