package javascript

import (
	"fmt"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/backend/responder"
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

// RequestContext contains context information about the request.
type RequestContext struct {
	eCol *extractors.ExtractorCollection
}

func (r *RequestContext) AllRequestMetadata() []database.RequestMetadata {
	return r.eCol.AllMetadata(0)
}

func (r *RequestContext) RequestMetadataByType(metaType string) []database.RequestMetadata {
	ret := []database.RequestMetadata{}

	for _, m := range r.eCol.AllMetadata(0) {
		if m.Type == metaType {
			ret = append(ret, m)
		}
	}

	return ret
}

type ResponderWrapper struct {
	responder responder.Responder
}

func (r *ResponderWrapper) Respond(resType string, promptInput string, template string) string {
	if r.responder == nil {
		slog.Warn("responder is nil")
		return ""
	}
	res, err := r.responder.Respond(resType, promptInput, template)
	if err != nil {
		slog.Error("error in responder", slog.String("error", err.Error()))
		return ""
	}

	return res
}
