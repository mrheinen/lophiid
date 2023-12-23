package database

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")
var AppTable = ksql.NewTable("app")
var RequestMetadataTable = ksql.NewTable("request_metadata")

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
	GetRequests() ([]Request, error)
	GetRequestsForSourceIP(ip string) ([]Request, error)
	GetRequestsSegment(offset int64, limit int64, source_ip *string) ([]Request, error)
	SearchRequests(offset int64, limit int64, params map[string]string) ([]Request, error)
	GetRequestsDistinctComboLastMonth() ([]Request, error)
	GetMetadataByRequestID(id int64) ([]RequestMetadata, error)
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
	default:
		return nil
	}
}

func (d *KSQLClient) Insert(dm DataModel) (DataModel, error) {
	t := d.getTableForModel(dm)
	if t == nil {
		return dm, fmt.Errorf("Unknown datamodel: %v", dm)
	}
	err := d.db.Insert(d.ctx, *t, dm)
	return dm, err
}

func (d *KSQLClient) Update(dm DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("Unknown datamodel: %v", dm)
	}
	return d.db.Patch(d.ctx, *t, dm)
}

func (d *KSQLClient) Delete(dm DataModel) error {
	t := d.getTableForModel(dm)
	if t == nil {
		return fmt.Errorf("Unknown datamodel: %v", dm)
	}
	return d.db.Delete(d.ctx, *t, dm.ModelID())
}

func (d *KSQLClient) GetApps() ([]Application, error) {
	var apps []Application
	err := d.db.Query(d.ctx, &apps, "FROM app ORDER BY name")
	return apps, err
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

func (d *KSQLClient) SearchRequests(offset int64, limit int64, params map[string]string) ([]Request, error) {
	var rs []Request

	baseQuery := "FROM request"

	idx := 1
	var values []interface{}
	for k, v := range params {
		if idx == 1 {
			baseQuery = fmt.Sprintf("%s WHERE %s = $%d ", baseQuery, k, idx)
			values = append(values, v)
		} else {
			baseQuery = fmt.Sprintf("%s AND %s = $%d ", baseQuery, k, idx)
			values = append(values, v)
		}

		idx++
	}

	baseQuery = fmt.Sprintf("%s ORDER BY time_received DESC OFFSET %d LIMIT %d", baseQuery, offset, limit)
	slog.Debug("Running query", slog.String("query", baseQuery), slog.Int("values", len(values)))
	start := time.Now()
	err := d.db.Query(d.ctx, &rs, baseQuery, values...)
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
func (f *FakeDatabaseClient) SearchRequests(offset int64, limit int64, params map[string]string) ([]Request, error) {
	return []Request{}, f.ErrorToReturn
}
