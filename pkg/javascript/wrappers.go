// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package javascript

import (
	"fmt"
	"log/slog"
	"lophiid/backend_service"
	"lophiid/pkg/backend/extractors"
	"lophiid/pkg/backend/responder"
	"lophiid/pkg/database/models"
	"lophiid/pkg/util"
)

type CacheWrapper struct {
	sourceIP   string
	honeypotIP string
	strCache   *util.StringMapCache[string]
}

// Set will set the cache value with the default key prefix. This limits the
// cache to the IP/honyport combination
func (c *CacheWrapper) Set(key string, value string) {
	fkey := fmt.Sprintf("%s-%s-%s", c.honeypotIP, c.sourceIP, key)
	c.strCache.Store(fkey, value)
}

func (c *CacheWrapper) Get(key string) string {
	fkey := fmt.Sprintf("%s-%s-%s", c.honeypotIP, c.sourceIP, key)
	val, err := c.strCache.Get(fkey)
	if err != nil {
		return ""
	}
	return *val
}

// SetOnSourceIP will set the cache value on the source IP.
func (c *CacheWrapper) SetOnSourceIP(key string, value string) {
	fkey := fmt.Sprintf("%s-%s", c.sourceIP, key)
	c.strCache.Store(fkey, value)
}

func (c *CacheWrapper) GetFromSourceIP(key string) string {
	fkey := fmt.Sprintf("%s-%s", c.sourceIP, key)
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

func (r *ResponseWrapper) GetHeader(key string) string {

	for _, hdr := range r.response.Header {
		if hdr.Key == key {
			return hdr.Value
		}
	}
	return ""
}

func (r *ResponseWrapper) SetBody(body string) {
	r.response.Body = []byte(body)
}

func (r *ResponseWrapper) SetStatusCode(code int) {
	r.response.StatusCode = fmt.Sprintf("%d", code)
}

func (r *ResponseWrapper) GetBody() string {
	return string(r.response.Body)
}

func (r *ResponseWrapper) BodyString() string {
	return string(r.response.Body)
}

// RequestContext contains context information about the request.
type RequestContext struct {
	eCol *extractors.ExtractorCollection
}

func (r *RequestContext) AllRequestMetadata() []models.RequestMetadata {
	return r.eCol.AllMetadata(0)
}

func (r *RequestContext) RequestMetadataByType(metaType string) []models.RequestMetadata {
	ret := []models.RequestMetadata{}

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
