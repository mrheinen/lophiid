// Lophiid distributed honeypot
// Copyright (C) 2026 Niels Heinen
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
package tools

import (
	"context"
	"encoding/json"
)

const (
	JSONStatusSuccess = "SUCCESS"
	JSONStatusError   = "ERROR"
)

// The JSON data wrapper that also includes a status to be used for
// communication with the LLM.
type JSONStatusReply struct {
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	Data          any    `json:"data"`
}

func (j *JSONStatusReply) JSON() string {
	jsonData, err := json.Marshal(j)
	if err != nil {
		return `{"status": "ERROR", "status_message": "error marshalling json", "data": {}`
	}
	return string(jsonData)
}

func GetJSONSuccessMessage(msg string, data any) string {
	ret := JSONStatusReply{
		Status:        JSONStatusSuccess,
		StatusMessage: msg,
		Data:          data,
	}

	return ret.JSON()
}

func GetJSONErrorMessage(msg string, data any) string {
	ret := JSONStatusReply{
		Status:        JSONStatusError,
		StatusMessage: msg,
		Data:          data,
	}

	return ret.JSON()
}

// SearchResult holds a single result from a web search.
type SearchResult struct {
	Title   string
	URL     string
	Snippet string
}

// SearchProvider abstracts web search so additional engines can be added.
type SearchProvider interface {
	Search(ctx context.Context, query string, maxResults int) ([]SearchResult, error)
}

// CreateDraftInput is the JSON payload expected by the CreateDraftTool.
type CreateDraftInput struct {
	App           *DraftApp    `json:"app,omitempty"`
	Content       DraftContent `json:"content"`
	Rule          DraftRule    `json:"rule"`
	Description   string       `json:"description"`
	Links         []string     `json:"links,omitempty"`
	BaseRequestID int64        `json:"base_request_id,omitempty"`
}

// DraftApp holds the fields for an optional new Application to create.
type DraftApp struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Vendor  string   `json:"vendor"`
	CVES    []string `json:"cves,omitempty"`
	Links   []string `json:"links,omitempty"`
}

// DraftContent holds the fields for the Content to create.
type DraftContent struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Data        string   `json:"data"`
	ContentType string   `json:"content_type,omitempty"`
	Server      string   `json:"server,omitempty"`
	StatusCode  string   `json:"status_code"`
	Headers     []string `json:"headers,omitempty"`
}

// DraftRule holds the fields for the ContentRule to create.
type DraftRule struct {
	URI            string `json:"uri"`
	URIMatching    string `json:"uri_matching"`
	Body           string `json:"body,omitempty"`
	BodyMatching   string `json:"body_matching,omitempty"`
	Method         string `json:"method"`
	RequestPurpose string `json:"request_purpose"`
	AppID          int64  `json:"app_id,omitempty"`
}
