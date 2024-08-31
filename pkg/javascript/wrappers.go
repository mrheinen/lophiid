package javascript

import (
	"fmt"
	"lophiid/backend_service"
	"lophiid/pkg/database"
	"lophiid/pkg/util"
)

type CacheWrapper struct {
	keyPrefix string
	strCache  *util.StringMapCache[string]
}

func (c *CacheWrapper) Set(key string, value string) {
	fkey := fmt.Sprintf("%s-%s", c.keyPrefix, key)
	c.strCache.Store(fkey, value)
}

func (c *CacheWrapper) Get(key string) string {
	fkey := fmt.Sprintf("%s-%s", c.keyPrefix, key)
	val, err := c.strCache.Get(fkey)
	if err != nil {
		return ""
	}
	return *val
}

// ResponseWrapper wraps the response and makes it available via methods in the
// javascript context.
type ResponseWrapper struct {
	response *backend_service.HttpResponse
}

func (r *ResponseWrapper) AddHeader(key string, value string) {
	r.response.Header = append(r.response.Header, &backend_service.KeyValue{
		Key:   key,
		Value: value,
	})
}

func (r *ResponseWrapper) SetBody(body string) {
	r.response.Body = []byte(body)
}

func (r *ResponseWrapper) GetBody() string {
	return string(r.response.Body)
}

func (r *ResponseWrapper) BodyString() string {
	return string(r.response.Body)
}

// ContentWrapper wraps the database.Content
type ContentWrapper struct {
	Content database.Content
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
