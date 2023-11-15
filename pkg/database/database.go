package database

import (
	"context"
	"fmt"
	"time"

	"github.com/vingarcia/ksql"
	kpgx "github.com/vingarcia/ksql/adapters/kpgx5"
)

var ContentTable = ksql.NewTable("content")
var ContentLocationTable = ksql.NewTable("content_location")

type Content struct {
	ID        int64     `ksql:"id,skipInserts"`
	Content   string    `ksql:"content"`
	Name      string    `ksql:"name"`
	CreatedAt time.Time `ksql:"created_at,skipInserts"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC"`
}

type PartialContent struct {
	ID        int64     `ksql:"id,skipInserts"`
	Content   string    `ksql:"content"`
	Name      string    `ksql:"name"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC"`
}

type ContentLocation struct {
	ID        int64     `ksql:"id,skipInserts"`
	Location  string    `ksql:"location"`
	ContentID int64     `ksql:"content_id"`
	CreatedAt time.Time `ksql:"created_at,skipInserts"`
	UpdatedAt time.Time `ksql:"updated_at,timeNowUTC"`
}

type PartialContentLocation struct {
	ID        int64  `ksql:"id,skipInserts"`
	Location  string `ksql:"location"`
	ContentID int64  `ksql:"content_id"`
	UpdatedAt string `ksql:"updated_at,timeNowUTC"`
}
type DatabaseClient struct {
	db  *ksql.DB
	ctx context.Context
}

// db, err := kpgx.New(ctx, "postgres://lo:test@localhost/lophiid", ksql.Config{
func (d *DatabaseClient) Init(connectString string) error {
	d.ctx = context.Background()

	db, err := kpgx.New(d.ctx, connectString, ksql.Config{
		MaxOpenConns: 3,
	})

	d.db = &db
	return err
}

func (d *DatabaseClient) Close() {
	if d.db == nil {
		fmt.Printf("Cannot close closed db")
		return
	}
	d.db.Close()
}

// InsertContent creates a new row in the content table, It does not check
// whether there already is a similar entry. This because we allow multiple
// entries with the same name.
func (d *DatabaseClient) InsertContent(name string, content string) (int64, error) {
	ct := &Content{
		Name:    name,
		Content: content,
	}

	err := d.db.Insert(d.ctx, ContentTable, ct)
	return ct.ID, err
}

func (d *DatabaseClient) UpdateContent(id int64, name string, content string) error {
	ct := &PartialContent{
		ID:      id,
		Name:    name,
		Content: content,
	}

	return d.db.Patch(d.ctx, ContentTable, ct)
}

func (d *DatabaseClient) GetContentByID(id int64) (Content, error) {
	ct := Content{}
	err := d.db.QueryOne(d.ctx, &ct, "FROM content WHERE id = ? ORDER BY id", id)
	return ct, err
}

func (d *DatabaseClient) GetContent() ([]Content, error) {
	var cts []Content
	err := d.db.Query(d.ctx, &cts, "FROM content")
	return cts, err
}

func (d *DatabaseClient) DeleteContent(id int64) error {
	return d.db.Delete(d.ctx, ContentTable, id)
}

func (d *DatabaseClient) InsertContentLocation(location string, id int64) (int64, error) {
	cl := &ContentLocation{
		Location:  location,
		ContentID: id,
	}

	err := d.db.Insert(d.ctx, ContentLocationTable, cl)
	return cl.ID, err
}

func (d *DatabaseClient) UpdateContentLocation(id int64, location string, contentId int64) error {
	cl := &PartialContentLocation{
		ID:        id,
		Location:  location,
		ContentID: contentId,
	}

	return d.db.Patch(d.ctx, ContentLocationTable, cl)
}

func (d *DatabaseClient) DeleteContentLocation(id int64) error {
	return d.db.Delete(d.ctx, ContentLocationTable, id)
}
