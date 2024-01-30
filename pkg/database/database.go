package database

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"loophid/pkg/util"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")
var AppTable = ksql.NewTable("app")
var RequestMetadataTable = ksql.NewTable("request_metadata")
var DownloadTable = ksql.NewTable("downloads")
var HoneypotTable = ksql.NewTable("honeypot")

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
	Starred       bool      `ksql:"starred" json:"starred"`
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
	ID               int64     `ksql:"id,skipInserts" json:"id"`
	IP               string    `ksql:"ip" json:"ip"`
	CreatedAt        time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt        time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
	LastCheckin      time.Time `ksql:"last_checkin,skipInserts,skipUpdates" json:"last_checkin"`
	DefaultContentID int64     `ksql:"default_content_id" json:"default_content_id"`
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
	ID            int64     `ksql:"id,skipInserts" json:"id"`
	RequestID     int64     `ksql:"request_id" json:"request_id"`
	Size          int64     `ksql:"size" json:"size"`
	Port          int64     `ksql:"port" json:"port"`
	CreatedAt     time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	LastSeenAt    time.Time `ksql:"last_seen_at,timeNowUTC" json:"last_seen_at"`
	ContentType   string    `ksql:"content_type" json:"content_type"`
	OriginalUrl   string    `ksql:"original_url" json:"original_url"`
	UsedUrl       string    `ksql:"used_url" json:"used_url"`
	IP            string    `ksql:"ip" json:"ip"`
	SHA256sum     string    `ksql:"sha256sum" json:"sha265sum"`
	Host          string    `ksql:"host" json:"host"`
	FileLocation  string    `ksql:"file_location" json:"file_location"`
	TimesSeen     int64     `ksql:"times_seen" json:"times_seen"`
	LastRequestID int64     `ksql:"last_request_id" json:"last_request_id"`
	VTAnalysisID  string    `ksql:"vt_analysis_id" json:"vt_analysis_id"`
}

func (c *Download) ModelID() int64 { return c.ID }

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
	GetHoneypots() ([]Honeypot, error)
	GetRequests() ([]Request, error)
	GetRequestsForSourceIP(ip string) ([]Request, error)
	GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error)
	SearchRequests(offset int64, limit int64, query string) ([]Request, error)
	SearchContentRules(offset int64, limit int64, query string) ([]ContentRule, error)
	SearchContent(offset int64, limit int64, query string) ([]Content, error)
	SearchDownloads(offset int64, limit int64, query string) ([]Download, error)
	SearchHoneypots(offset int64, limit int64, query string) ([]Honeypot, error)
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
		return dl, fmt.Errorf("found no download for hash: %s", sha256sum)
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
	// TODO: once last_checkin is set, order the result by it.
	err := d.db.Query(d.ctx, &rs, "FROM honeypot")
	return rs, err
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

	params, err := ParseQuery(query, getDatamodelDatabaseFields(Request{}))
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

	params, err := ParseQuery(query, getDatamodelDatabaseFields(ContentRule{}))
	if err != nil {
		return rs, fmt.Errorf("cannot parse query \"%s\" -> %s", query, err.Error())
	}

	query, values, err := buildQuery(params, "FROM content_rule", fmt.Sprintf("ORDER BY app_id,created_at DESC OFFSET %d LIMIT %d", offset, limit))
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

	query, values, err := buildQuery(params, "FROM content", fmt.Sprintf("ORDER BY id DESC OFFSET %d LIMIT %d", offset, limit))
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

	query, values, err := buildQuery(params, "FROM app", fmt.Sprintf("OFFSET %d LIMIT %d", offset, limit))
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
	query, values, err := buildQuery(params, "FROM downloads", fmt.Sprintf("ORDER BY last_seen_at DESC OFFSET %d LIMIT %d", offset, limit))
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

	query, values, err := buildQuery(params, "FROM honeypot", fmt.Sprintf("ORDER BY last_checkin DESC OFFSET %d LIMIT %d", offset, limit))
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
	ContentIDToReturn     int64
	ContentsToReturn      map[int64]Content
	ErrorToReturn         error
	ContentRuleIDToReturn int64
	ContentRulesToReturn  []ContentRule
	RequestsToReturn      []Request
	DownloadsToReturn     []Download
	ApplicationToReturn   Application
	HoneypotToReturn      Honeypot
	HoneypotErrorToReturn error
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
	return []Download{}, nil
}
func (f *FakeDatabaseClient) SearchHoneypots(offset int64, limit int64, query string) ([]Honeypot, error) {
	return []Honeypot{}, nil
}
