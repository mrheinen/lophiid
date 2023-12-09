package database

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")
var AppTable = ksql.NewTable("app")

type DataModel interface {
	ModelID() int64
}
type Content struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	Content     string    `ksql:"content"        json:"content"`
	Name        string    `ksql:"name"           json:"name"`
	Description string    `ksql:"description"    json:"description"`
	ContentType string    `ksql:"content_type"   json:"content_type"`
	Server      string    `ksql:"server"         json:"server"`
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
	Body          string    `ksql:"body" json:"body"`
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
	Insert(dm DataModel) (int64, error)
	Update(dm DataModel) error
	Delete(dm DataModel) error
	GetContentByID(id int64) (Content, error)
	GetContent() ([]Content, error)
	GetContentRuleByID(id int64) (ContentRule, error)
	GetContentRules() ([]ContentRule, error)
	GetRequests() ([]Request, error)
	GetRequestsSegment(offset int64, limit int64) ([]Request, error)
	GetRequestUniqueKeyPerSourceIP() (map[string][]string, error)
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
	case "App":
		return &AppTable
	case "Request":
		return &RequestTable
	case "Content":
		return &ContentTable
	case "ContentRule":
		return &ContentRuleTable
	default:
		return nil
	}
}

func (d *KSQLClient) Insert(dm DataModel) (int64, error) {
	t := d.getTableForModel(dm)
	if t == nil {
		return 0, fmt.Errorf("Unknown datamodel: %v", dm)
	}
	err := d.db.Insert(d.ctx, *t, dm)
	return dm.ModelID(), err
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

func (d *KSQLClient) GetRequests() ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "FROM request ORDER BY time_received")
	return rs, err
}

func (d *KSQLClient) GetRequestsSegment(offset int64, limit int64) ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "FROM request ORDER BY time_received DESC OFFSET $1 LIMIT $2", offset, limit)
	return rs, err

}

func (d *KSQLClient) GetRequestUniqueKeyPerSourceIP() (map[string][]string, error) {
	var rs []Request
	ret := make(map[string][]string)
	err := d.db.Query(d.ctx, &rs, "SELECT DISTINCT source_ip, content_id, rule_id FROM request WHERE content_id > 0 AND time_received >= date_trunc('month', current_date - interval '1'month);")
	if err != nil {
		return ret, err
	}

	for _, req := range rs {
		k := fmt.Sprintf("%d-%d", req.RuleID, req.ContentID)
		if _, ok := ret[req.SourceIP]; ok {
			ret[req.SourceIP] = append(ret[req.SourceIP], k)
		} else {
			ret[req.SourceIP] = []string{k}
		}
	}
	return ret, err
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
	err := d.db.Query(d.ctx, &cts, "FROM content_rule")
	return cts, err
}

func (d *KSQLClient) DeleteContentRule(id int64) error {
	return d.db.Delete(d.ctx, ContentRuleTable, id)
}

// FakeDatabaseClient is a struct specifically for testing users of the
// DatabaseClient interface
type FakeDatabaseClient struct {
	ContentIDToReturn          int64
	ContentsToReturn           map[int64]Content
	ErrorToReturn              error
	ContentRuleIDToReturn      int64
	ContentRulesToReturn       []ContentRule
	UniqueKeyPerSourceToReturn map[string][]string
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
func (f *FakeDatabaseClient) GetRequestsSegment(offset int64, limit int64) ([]Request, error) {
	return []Request{}, nil
}
func (f *FakeDatabaseClient) GetRequestUniqueKeyPerSourceIP() (map[string][]string, error) {
	return f.UniqueKeyPerSourceToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Insert(dm DataModel) (int64, error) {
	return 42, nil
}

func (f *FakeDatabaseClient) Update(dm DataModel) error {
	return f.ErrorToReturn
}

func (f *FakeDatabaseClient) Delete(dm DataModel) error {
	return f.ErrorToReturn
}
