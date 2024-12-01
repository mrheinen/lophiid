package javascript

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
)

// ContentWrapper wraps the models.Content
type ContentWrapper struct {
	Content models.Content
}

func (c *ContentWrapper) GetData() string {
	return string(c.Content.Data)
}

func (c *ContentWrapper) GetID() int64 {
	return c.Content.ID
}

func (c *ContentWrapper) GetContentType() string {
	return c.Content.ContentType
}

// The DatabaseClientWrapper exposes database functions to ze Javascripts
// Only update this to expose read functions.
type DatabaseClientWrapper struct {
	dbClient database.DatabaseClient
}

func (d *DatabaseClientWrapper) GetContentById(id int64) *ContentWrapper {
	cn, err := d.dbClient.GetContentByID(id)
	if err != nil {
		return nil
	}

	return &ContentWrapper{Content: cn}
}

// GetContentByUUID searches the database for a content with the given UUID. If
// it finds one it returns a ContentWrapper, otherwise it returns nil.
func (d *DatabaseClientWrapper) GetContentByUUID(uuid string) *ContentWrapper {
	cn, err := d.dbClient.SearchContent(0, 1, fmt.Sprintf("uuid:%s", uuid))
	if err != nil || len(cn) == 0 {
		return nil
	}

	return &ContentWrapper{Content: cn[0]}
}
