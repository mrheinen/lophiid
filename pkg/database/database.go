package database

import (
	"context"
	"fmt"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentRuleTable = ksql.NewTable("content_rule")
var RequestTable = ksql.NewTable("request")

type Content struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	Content     string    `ksql:"content"        json:"content"`
	Name        string    `ksql:"name"           json:"name"`
	ContentType string    `ksql:"content_type"   json:"content_type"`
	Server      string    `ksql:"server"         json:"server"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC"  json:"updated_at"`
}

type PartialContent struct {
	ID          int64     `ksql:"id,skipInserts"`
	Content     string    `ksql:"content"`
	ContentType string    `ksql:"content_type"`
	Server      string    `ksql:"server"`
	Name        string    `ksql:"name"`
	UpdatedAt   time.Time `ksql:"updated_at,timeNowUTC"`
}

type ContentRule struct {
	ID           int64     `ksql:"id,skipInserts" json:"id"`
	Path         string    `ksql:"path" json:"path"`
	PathMatching string    `ksql:"path_matching" json:"path_matching"`
	Body         string    `ksql:"body" json:"body"`
	BodyMatching string    `ksql:"body_matching" json:"body_matching"`
	Method       string    `ksql:"method" json:"method"`
	ContentID    int64     `ksql:"content_id" json:"content_id"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

type PartialContentRule struct {
	ID           int64     `ksql:"id,skipInserts" json:"id"`
	Path         string    `ksql:"path" json:"path"`
	PathMatching string    `ksql:"path_matching" json:"path_matching"`
	Body         string    `ksql:"body" json:"body"`
	BodyMatching string    `ksql:"body_matching" json:"body_matching"`
	Method       string    `ksql:"method" json:"method"`
	ContentID    int64     `ksql:"content_id" json:"content_id"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

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
	SourceIP      string    `ksql:"source_ip" json:"source_ip"`
	SourcePort    int64     `ksql:"source_port" json:"source_port"`
	Raw           string    `ksql:"raw" json:"raw"`
	CreatedAt     time.Time `ksql:"created_at,skipInserts,skipUpdates" json:"created_at"`
	UpdatedAt     time.Time `ksql:"updated_at,timeNowUTC" json:"updated_at"`
}

type DatabaseClient interface {
	Close()
	InsertContent(c *Content) (int64, error)
	UpdateContent(c *Content) error
	GetContentByID(id int64) (Content, error)
	GetContent() ([]Content, error)
	DeleteContent(id int64) error
	InsertContentRule(cr *ContentRule) (int64, error)
	UpdateContentRule(cr *ContentRule) error
	GetContentRuleByID(id int64) (ContentRule, error)
	GetContentRules() ([]ContentRule, error)
	DeleteContentRule(id int64) error
	InsertRequest(r *Request) (int64, error)
	GetRequests() ([]Request, error)
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

func (d *KSQLClient) InsertRequest(r *Request) (int64, error) {
	err := d.db.Insert(d.ctx, RequestTable, r)
	return r.ID, err
}

func (d *KSQLClient) GetRequests() ([]Request, error) {
	var rs []Request
	err := d.db.Query(d.ctx, &rs, "FROM request")
	return rs, err
}

// InsertContent creates a new row in the content table, It does not check
// whether there already is a similar entry. This because we allow multiple
// entries with the same name.
func (d *KSQLClient) InsertContent(c *Content) (int64, error) {
	err := d.db.Insert(d.ctx, ContentTable, c)
	return c.ID, err
}

func (d *KSQLClient) UpdateContent(c *Content) error {
	return d.db.Patch(d.ctx, ContentTable, c)
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

func (d *KSQLClient) DeleteContent(id int64) error {
	return d.db.Delete(d.ctx, ContentTable, id)
}

func (d *KSQLClient) InsertContentRule(cr *ContentRule) (int64, error) {
	err := d.db.Insert(d.ctx, ContentRuleTable, cr)
	return cr.ID, err
}

func (d *KSQLClient) UpdateContentRule(cr *ContentRule) error {
	return d.db.Patch(d.ctx, ContentRuleTable, cr)
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
	ContentIDToReturn     int64
	ContentToReturn       Content
	ErrorToReturn         error
	ContentRuleIDToReturn int64
	ContentRuleToReturn   ContentRule
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) InsertContent(c *Content) (int64, error) {
	return f.ContentIDToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) UpdateContent(c *Content) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentRuleByID(id int64) (ContentRule, error) {
	return f.ContentRuleToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (Content, error) {
	return f.ContentToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContent() ([]Content, error) {
	return []Content{f.ContentToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) DeleteContent(id int64) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) UpdateContentRule(id int64, contentId int64, path string, pathMatching string, method string, body string, bodyMatching string) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentRules() ([]ContentRule, error) {
	return []ContentRule{f.ContentRuleToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) DeleteContentRule(id int64) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetRequests() ([]Request, error) {
	return []Request{}, nil
}
func (f *FakeDatabaseClient) InsertRequest(r *Request) (int64, error) {
	return 42, nil
}
func (f *FakeDatabaseClient) InsertContentRule(cr *ContentRule) (int64, error) {
	return f.ContentRuleIDToReturn, f.ErrorToReturn
}
