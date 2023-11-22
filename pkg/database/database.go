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

type Content struct {
	ID          int64     `ksql:"id,skipInserts" json:"id"`
	Content     string    `ksql:"content"        json:"content"`
	Name        string    `ksql:"name"           json:"name"`
	ContentType string    `ksql:"content_type"   json:"content_type"`
	Server      string    `ksql:"server"         json:"server"`
	CreatedAt   time.Time `ksql:"created_at,skipInserts" json:"created_at"`
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
	ID           int64     `ksql:"id,skipInserts"`
	Path         string    `ksql:"path"`
	PathMatching string    `ksql:"path_matching"`
	Body         string    `ksql:"body"`
	BodyMatching string    `ksql:"body_matching"`
	Method       string    `ksql:"method"`
	ContentID    int64     `ksql:"content_id"`
	CreatedAt    time.Time `ksql:"created_at,skipInserts"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC"`
}

type PartialContentRule struct {
	ID           int64     `ksql:"id,skipInserts"`
	Path         string    `ksql:"path"`
	PathMatching string    `ksql:"path_matching"`
	Body         string    `ksql:"body"`
	BodyMatching string    `ksql:"body_matching"`
	Method       string    `ksql:"method"`
	ContentID    int64     `ksql:"content_id"`
	UpdatedAt    time.Time `ksql:"updated_at,timeNowUTC"`
}

type DatabaseClient interface {
	Close()
	InsertContent(name string, content string, contentType string, server string) (int64, error)
	UpdateContent(id int64, name string, content string, contentType string, server string) error
	GetContentByID(id int64) (Content, error)
	GetContent() ([]Content, error)
	DeleteContent(id int64) error
	InsertContentRule(id int64, path string, pathMatching string, method string, body string, bodyMatching string) (int64, error)
	UpdateContentRule(id int64, path string, contentId int64) error
	GetContentRules() ([]ContentRule, error)
	DeleteContentRule(id int64) error
}

type PostgresClient struct {
	db  *ksql.DB
	ctx context.Context
}

// db, err := kpgx.New(ctx, "postgres://lo:test@localhost/lophiid", ksql.Config{
func (d *PostgresClient) Init(connectString string) error {
	d.ctx = context.Background()

	db, err := kpgx.New(d.ctx, connectString, ksql.Config{
		MaxOpenConns: 3,
	})

	d.db = &db
	return err
}

func (d *PostgresClient) Close() {
	if d.db == nil {
		fmt.Printf("Cannot close closed db")
		return
	}
	d.db.Close()
}

// InsertContent creates a new row in the content table, It does not check
// whether there already is a similar entry. This because we allow multiple
// entries with the same name.
func (d *PostgresClient) InsertContent(name string, content string, contentType string, server string) (int64, error) {
	ct := &Content{
		Name:        name,
		Content:     content,
		ContentType: contentType,
		Server:      server,
	}

	err := d.db.Insert(d.ctx, ContentTable, ct)
	return ct.ID, err
}

func (d *PostgresClient) UpdateContent(id int64, name string, content string, contentType string, server string) error {
	ct := &PartialContent{
		ID:          id,
		Name:        name,
		Content:     content,
		ContentType: contentType,
		Server:      server,
	}
	return d.db.Patch(d.ctx, ContentTable, ct)
}

func (d *PostgresClient) GetContentByID(id int64) (Content, error) {
	ct := Content{}
	err := d.db.QueryOne(d.ctx, &ct, fmt.Sprintf("FROM content WHERE id = %d", id))
	return ct, err
}

func (d *PostgresClient) GetContent() ([]Content, error) {
	var cts []Content
	err := d.db.Query(d.ctx, &cts, "FROM content")
	return cts, err
}

func (d *PostgresClient) DeleteContent(id int64) error {
	return d.db.Delete(d.ctx, ContentTable, id)
}

func (d *PostgresClient) InsertContentRule(id int64, path string, pathMatching string, method string, body string, bodyMatching string) (int64, error) {
	cl := &ContentRule{
		Path:         path,
		ContentID:    id,
		PathMatching: pathMatching,
		Method:       method,
		Body:         body,
		BodyMatching: bodyMatching,
	}

	err := d.db.Insert(d.ctx, ContentRuleTable, cl)
	return cl.ID, err
}

func (d *PostgresClient) UpdateContentRule(id int64, path string, contentId int64) error {
	cl := &PartialContentRule{
		ID:        id,
		Path:      path,
		ContentID: contentId,
	}

	return d.db.Patch(d.ctx, ContentRuleTable, cl)
}

func (d *PostgresClient) GetContentRules() ([]ContentRule, error) {
	var cts []ContentRule
	err := d.db.Query(d.ctx, &cts, "FROM content_rule")
	return cts, err
}

func (d *PostgresClient) DeleteContentRule(id int64) error {
	return d.db.Delete(d.ctx, ContentRuleTable, id)
}

// FakeDatabaseClient is a struct specifically for testing users of the
// DatabaseClient interface
type FakeDatabaseClient struct {
	ContentIDToReturn     int64
	ContentToReturn       Content
	ContentRuleIDToReturn int64
	ContentRuleToReturn   ContentRule
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) InsertContent(name string, content string, contentType string) (int64, error) {
	return f.ContentIDToReturn, nil
}
func (f *FakeDatabaseClient) UpdateContent(id int64, name string, content string, contentType string) error {
	return nil
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (Content, error) {
	return f.ContentToReturn, nil
}
func (f *FakeDatabaseClient) GetContent() ([]Content, error) {
	return []Content{f.ContentToReturn}, nil
}
func (f *FakeDatabaseClient) DeleteContent(id int64) error {
	return nil
}
func (f *FakeDatabaseClient) InsertContentRule(id int64, path string, pathMatching string, method string, body string, bodyMatching string) (int64, error) {
	return f.ContentRuleIDToReturn, nil
}
func (f *FakeDatabaseClient) UpdateContentRule(id int64, path string, contentId int64) error {
	return nil
}
func (f *FakeDatabaseClient) GetContentRules() ([]ContentRule, error) {
	return []ContentRule{f.ContentRuleToReturn}, nil
}
func (f *FakeDatabaseClient) DeleteContentRule(id int64) error {
	return nil
}
